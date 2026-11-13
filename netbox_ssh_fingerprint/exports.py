"""
Build known_hosts files and SSHFP records from host keys.
"""
import base64
from collections import defaultdict

from django.contrib.contenttypes.models import ContentType
from django.db.models import Max, Q

from dcim.models import Interface
from ipam.models import FHRPGroup, FHRPGroupAssignment, IPAddress, Service
from netbox.plugins import get_plugin_config
from virtualization.models import VMInterface

from .choices import HostKeyEndpointChoices, HostKeyStatusChoices
from .keys import canonical_ip, host_pattern, known_hosts_lines, sshfp_records

INCLUDE_CHOICES = ('both', 'names', 'ips')


def _config(name):
    return get_plugin_config('netbox_ssh_fingerprint', name)


def export_queryset(queryset):
    return queryset.select_related(
        'device__primary_ip4', 'device__primary_ip6', 'device__oob_ip', 'device__virtual_chassis',
        'virtual_machine__primary_ip4', 'virtual_machine__primary_ip6',
    ).order_by('device__name', 'virtual_machine__name', 'endpoint', 'key_type', 'pk')


def ssh_ports(hosts):
    """
    Non-standard SSH ports from NetBox services named like the ssh_service_name setting,
    keyed by (content type id, object id). One query per host model.
    """
    by_type = defaultdict(set)
    for host in hosts:
        by_type[ContentType.objects.get_for_model(host).pk].add(host.pk)
    ports = {}
    for ct_id, ids in by_type.items():
        services = Service.objects.filter(
            parent_object_type_id=ct_id, parent_object_id__in=ids,
            name__iexact=_config('ssh_service_name'), protocol='tcp',
        )
        for svc in services:
            if svc.ports:
                ports.setdefault((ct_id, svc.parent_object_id), svc.ports[0])
    return ports


def endpoint_addresses(key):
    host = key.host
    if key.endpoint == HostKeyEndpointChoices.OOB:
        return [ip for ip in [getattr(host, 'oob_ip', None)] if ip]
    return [ip for ip in (host.primary_ip4, host.primary_ip6) if ip]


def host_names(key):
    """
    Names under which users reach the endpoint: for the host its NetBox name, the name with each
    configured domain suffix and the DNS names of its primary IPs; for out-of-band only DNS names.
    """
    names = []
    if key.endpoint == HostKeyEndpointChoices.HOST and key.host.name:
        names.append(key.host.name)
        names += [f'{key.host.name}.{suffix.strip(".")}' for suffix in _config('domain_suffixes')]
        # The master of a virtual chassis answers for the whole stack
        vc = getattr(key.host, 'virtual_chassis', None)
        if vc and vc.master_id == key.host.pk and vc.name:
            names.append(vc.name)
    names += [ip.dns_name for ip in endpoint_addresses(key) if ip.dns_name]
    return list(dict.fromkeys(names))


def host_patterns(key, include='both', ports=None):
    names = host_names(key) if include in ('both', 'names') else []
    ips = [canonical_ip(ip.address) for ip in endpoint_addresses(key)] if include in ('both', 'ips') else []
    port = 22
    if ports and key.endpoint == HostKeyEndpointChoices.HOST:
        port = ports.get((ContentType.objects.get_for_model(key.host).pk, key.host.pk), 22)
    return [host_pattern(p, port) for p in names + ips]


def vip_lines(keys, include='both', hashed=False):
    """
    known_hosts lines for the virtual IPs of FHRP groups (VRRP, HSRP, ...): the VIP moves between the
    members, so it is listed with the active keys of every member. OpenSSH accepts any of them.
    """
    host_keys = defaultdict(list)
    for key in keys:
        if key.endpoint == HostKeyEndpointChoices.HOST and key.status == HostKeyStatusChoices.ACTIVE:
            host_keys[(key.host._meta.model_name, key.host.pk)].append(key)
    if not host_keys:
        return []
    device_ids = [pk for model, pk in host_keys if model == 'device']
    vm_ids = [pk for model, pk in host_keys if model == 'virtualmachine']
    iface_host = {pk: ('device', dev) for pk, dev in
                  Interface.objects.filter(device_id__in=device_ids).values_list('pk', 'device_id')}
    vmiface_host = {pk: ('virtualmachine', vm) for pk, vm in
                    VMInterface.objects.filter(virtual_machine_id__in=vm_ids).values_list('pk', 'virtual_machine_id')}
    iface_ct = ContentType.objects.get_for_model(Interface)
    vmiface_ct = ContentType.objects.get_for_model(VMInterface)
    members = defaultdict(set)
    assignments = FHRPGroupAssignment.objects.filter(
        Q(interface_type=iface_ct, interface_id__in=list(iface_host))
        | Q(interface_type=vmiface_ct, interface_id__in=list(vmiface_host))
    ).values_list('group_id', 'interface_type_id', 'interface_id')
    for group_id, ct_id, iface_id in assignments:
        members[group_id].add((iface_host if ct_id == iface_ct.pk else vmiface_host)[iface_id])
    vips = IPAddress.objects.filter(
        assigned_object_type=ContentType.objects.get_for_model(FHRPGroup), assigned_object_id__in=list(members),
    ).order_by('address')
    lines = []
    for vip in vips:
        patterns = []
        if include in ('both', 'names') and vip.dns_name:
            patterns.append(vip.dns_name)
        if include in ('both', 'ips'):
            patterns.append(canonical_ip(vip.address))
        for host in sorted(members[vip.assigned_object_id]):
            for key in host_keys[host]:
                lines += known_hosts_lines(patterns, key.key_type, key.public_key, hashed=hashed)
    return lines


def known_hosts(queryset, include='both', hashed=False, revoked=True, vips=True):
    """
    Active keys as normal entries, revoked keys with @revoked so ssh refuses them. Pending keys are left out.
    revoked=False drops the @revoked lines for clients that cannot parse them (Paramiko, so Netmiko and
    Ansible network_cli); those reject unknown keys anyway.
    """
    statuses = [HostKeyStatusChoices.ACTIVE] + ([HostKeyStatusChoices.REVOKED] if revoked else [])
    keys = list(export_queryset(queryset.filter(status__in=statuses)))
    ports = ssh_ports({k.host for k in keys if k.endpoint == HostKeyEndpointChoices.HOST})
    lines = []
    for key in keys:
        lines += known_hosts_lines(
            host_patterns(key, include, ports), key.key_type, key.public_key,
            revoked=key.status == HostKeyStatusChoices.REVOKED, hashed=hashed,
        )
    if vips:
        lines += vip_lines(keys, include, hashed)
    return '\n'.join(lines) + ('\n' if lines else '')


def sshfp_owner(key):
    """
    The record owner: the first DNS name of the endpoint as an absolute name, else the bare host name
    (relative to the zone the snippet is included in). Out-of-band endpoints need a DNS name.
    """
    dns_names = [ip.dns_name for ip in endpoint_addresses(key) if ip.dns_name]
    if dns_names:
        return dns_names[0].rstrip('.') + '.'
    if key.endpoint == HostKeyEndpointChoices.HOST and key.host.name:
        return key.host.name
    return None


def sshfp_zone(queryset):
    keys = export_queryset(queryset.filter(status=HostKeyStatusChoices.ACTIVE))
    fp_types = _config('sshfp_fingerprint_types')
    lines = []
    for key in keys:
        owner = sshfp_owner(key)
        if owner:
            lines += sshfp_records(owner, key.key_type, base64.b64decode(key.public_key), fp_types)
    return '\n'.join(lines) + ('\n' if lines else '')


def last_modified(queryset):
    return queryset.aggregate(m=Max('last_updated'))['m']
