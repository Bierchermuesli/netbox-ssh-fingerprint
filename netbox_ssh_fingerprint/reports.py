"""
Report queries: hosts without keys, stale keys, mismatches, weak keys, duplicates and the algorithms
the hosts offer (post-quantum readiness).
"""
from collections import Counter
from datetime import timedelta

from django.db.models import Count, Exists, OuterRef, Q
from django.utils import timezone

from dcim.models import Device
from netbox.plugins import get_plugin_config
from virtualization.models import VirtualMachine

from .choices import HostKeyEndpointChoices, HostKeyStatusChoices
from .models import EndpointScan, HostKey
from .scope import scope_filter

LIMIT = 10


HOST_KINDS = {
    'without-key': 'without SSH host key',
    'no-pq': 'without post-quantum key exchange',
    'weak-algorithms': 'offering weak algorithms',
    'unreachable': 'not reachable by SSH',
}


def host_list_config(name):
    """
    NetBox's own filterset, filter form and table for the host lists of the report.
    """
    from dcim import filtersets as dcim_filtersets, forms as dcim_forms, tables as dcim_tables
    from virtualization import filtersets as vm_filtersets, forms as vm_forms, tables as vm_tables

    return {
        'devices': {'model': Device, 'label': 'Devices', 'filterset': dcim_filtersets.DeviceFilterSet,
                    'filterset_form': dcim_forms.DeviceFilterForm, 'table': dcim_tables.DeviceTable},
        'virtual-machines': {'model': VirtualMachine, 'label': 'Virtual machines',
                             'filterset': vm_filtersets.VirtualMachineFilterSet,
                             'filterset_form': vm_forms.VirtualMachineFilterForm,
                             'table': vm_tables.VirtualMachineTable},
    }.get(name)


def host_kind_queryset(model, kind, algorithm=None):
    """
    Hosts of one report section, as a queryset of the model so NetBox's own list view can show it.
    """
    field = 'device' if model is Device else 'virtual_machine'
    qs = model.objects.all()
    if kind == 'without-key':
        active = HostKey.objects.filter(
            **{field: OuterRef('pk')}, endpoint=HostKeyEndpointChoices.HOST, status=HostKeyStatusChoices.ACTIVE)
        qs = qs.filter(Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False), scope_filter(model))
        if model is Device:  # stack members are covered by the master's keys
            qs = qs.filter(Q(virtual_chassis__isnull=True) | Q(vc_master_for__isnull=False))
        return qs.exclude(Exists(active))
    scans = EndpointScan.objects.filter(**{field: OuterRef('pk')})
    if kind == 'no-pq':
        scans = scans.filter(reachable=True, pq_ready=False)
    elif kind == 'unreachable':
        scans = scans.filter(reachable=False)
    elif kind == 'weak-algorithms':
        scans = scans.filter(reachable=True).exclude(weak_algorithms=[])
        if algorithm:
            scans = scans.filter(weak_algorithms__contains=[algorithm])
    return qs.filter(Exists(scans))


def hosts_without_key(user):
    """
    Devices and VMs in scope (device_roles, vm_roles) with a primary IP but no active host key.
    """
    out = []
    for model, field in ((Device, 'device'), (VirtualMachine, 'virtual_machine')):
        active = HostKey.objects.filter(
            **{field: OuterRef('pk')}, endpoint=HostKeyEndpointChoices.HOST, status=HostKeyStatusChoices.ACTIVE,
        )
        qs = model.objects.restrict(user, 'view').filter(
            Q(primary_ip4__isnull=False) | Q(primary_ip6__isnull=False), scope_filter(model),
        ).exclude(Exists(active)).order_by('name')
        if model is Device:  # stack members are covered by the master's keys
            qs = qs.filter(Q(virtual_chassis__isnull=True) | Q(vc_master_for__isnull=False))
        out.append((model._meta.verbose_name_plural, qs.count(), list(qs[:LIMIT])))
    return out


def stale_keys(user):
    days = get_plugin_config('netbox_ssh_fingerprint', 'stale_days')
    cutoff = timezone.now() - timedelta(days=days)
    qs = HostKey.objects.restrict(user, 'view').filter(status=HostKeyStatusChoices.ACTIVE)
    never = qs.filter(last_seen__isnull=True)
    old = qs.filter(last_seen__lt=cutoff).order_by('last_seen')
    return days, never.count(), old.count(), list(old[:LIMIT])


def mismatches(user):
    """
    Pending keys of a type for which the host already has an active key: the host presented a different
    key than the one on record.
    """
    active = HostKey.objects.filter(
        Q(device=OuterRef('device'), device__isnull=False)
        | Q(virtual_machine=OuterRef('virtual_machine'), virtual_machine__isnull=False),
        endpoint=OuterRef('endpoint'), key_type=OuterRef('key_type'), status=HostKeyStatusChoices.ACTIVE,
    )
    qs = HostKey.objects.restrict(user, 'view').filter(status=HostKeyStatusChoices.PENDING).filter(
        Exists(active)).order_by('-last_seen')
    return qs.count(), list(qs[:LIMIT])


def weak_keys(user):
    qs = HostKey.objects.restrict(user, 'view').filter(
        Q(key_type='ssh-dss') | Q(key_type='ssh-rsa', bits__lt=2048),
    ).exclude(status=HostKeyStatusChoices.REVOKED)
    by_type = Counter(f'{k} {b}' for k, b in qs.values_list('key_type', 'bits'))
    return qs.count(), sorted(by_type.items(), key=lambda x: -x[1]), list(qs[:LIMIT])


def duplicates(user):
    """
    The same key on more than one host. Shared keys (HA pairs, VIPs) are listed but marked as intended.
    """
    qs = HostKey.objects.restrict(user, 'view').exclude(status=HostKeyStatusChoices.REVOKED)
    groups = (
        qs.values('fingerprint_sha256', 'key_type')
        .annotate(hosts=Count('device', distinct=True) + Count('virtual_machine', distinct=True),
                  unshared=Count('pk', filter=Q(shared=False)))
        .filter(hosts__gt=1)
        .order_by('-hosts', 'fingerprint_sha256')
    )
    rows = []
    for group in groups[:LIMIT]:
        keys = list(qs.filter(fingerprint_sha256=group['fingerprint_sha256']).select_related(
            'device', 'virtual_machine'))
        rows.append({**group, 'intended': group['unshared'] == 0, 'keys': keys})
    return groups.count(), rows


def _host_counts(user, kind, algorithm=None):
    """
    (devices, VMs) in a host report section, for the links to the lists.
    """
    return tuple(
        host_kind_queryset(model, kind, algorithm).restrict(user, 'view').count()
        for model in (Device, VirtualMachine)
    )


def algorithms(user):
    """
    What the scanned endpoints offer: post-quantum key exchange and weak algorithms.
    """
    device_ids = Device.objects.restrict(user, 'view').values('pk')
    vm_ids = VirtualMachine.objects.restrict(user, 'view').values('pk')
    scans = EndpointScan.objects.filter(
        Q(device__in=device_ids) | Q(virtual_machine__in=vm_ids),
    ).select_related('device', 'virtual_machine')
    reachable = scans.filter(reachable=True)
    weak_counter = Counter()
    for algs in reachable.values_list('weak_algorithms', flat=True):
        weak_counter.update(algs)
    software = Counter(reachable.values_list('banner', flat=True))
    return {
        'not_pq_hosts': _host_counts(user, 'no-pq'),
        'unreachable_hosts': _host_counts(user, 'unreachable'),
        'weak_hosts': _host_counts(user, 'weak-algorithms'),
        'scanned': scans.count(),
        'reachable': reachable.count(),
        'unreachable': list(scans.filter(reachable=False).order_by('-scanned_at')[:LIMIT]),
        'pq_ready': reachable.filter(pq_ready=True).count(),
        'not_pq': list(reachable.filter(pq_ready=False).order_by('device__name', 'virtual_machine__name')[:LIMIT]),
        'not_pq_count': reachable.filter(pq_ready=False).count(),
        'with_weak': reachable.exclude(weak_algorithms=[]).count(),
        'weak_algorithms': weak_counter.most_common(),
        'software': software.most_common(15),
    }


def _software(banner):
    """
    "SSH-2.0-OpenSSH_10.0p2 Debian-7" -> "OpenSSH 10.0"; "SSH-2.0-Cisco-1.25" -> "Cisco-1.25".
    """
    soft = banner.split('-', 2)[-1].split(' ')[0] if banner.startswith('SSH-') else banner
    if soft.startswith('OpenSSH_'):
        version = soft[len('OpenSSH_'):].split('p')[0]
        return f'OpenSSH {version}'
    return soft.replace('_', ' ')


def charts(user):
    """
    Data for the donut charts: active key types, best key exchange offered, SSH software.
    """
    from .charts import donut, top_n
    from .policy import PQ_KEX, weak_reason

    keys = HostKey.objects.restrict(user, 'view').filter(status=HostKeyStatusChoices.ACTIVE)
    types = Counter()
    for key_type, bits in keys.values_list('key_type', 'bits'):
        if key_type == 'ssh-dss' or (key_type == 'ssh-rsa' and bits < 2048):
            types['weak (DSA, RSA < 2048)'] += 1
        elif key_type.startswith('ecdsa-'):
            types['ECDSA'] += 1
        else:
            types[{'ssh-ed25519': 'Ed25519', 'ssh-ed448': 'Ed448', 'ssh-rsa': 'RSA'}[key_type]] += 1
    type_colors = {'Ed25519': 'green', 'Ed448': 'cyan', 'ECDSA': 'blue', 'RSA': 'purple',
                   'weak (DSA, RSA < 2048)': 'red'}

    device_ids = Device.objects.restrict(user, 'view').values('pk')
    vm_ids = VirtualMachine.objects.restrict(user, 'view').values('pk')
    scans = EndpointScan.objects.filter(Q(device__in=device_ids) | Q(virtual_machine__in=vm_ids), reachable=True)
    kex = Counter()
    software = Counter()
    for offered, banner in scans.values_list('kex', 'banner'):
        offered = [k for k in offered if not k.startswith(('ext-info-', 'kex-strict-'))]
        if any(k in PQ_KEX for k in offered):
            kex['post-quantum'] += 1
        elif any(not weak_reason('kex', k) for k in offered):
            kex['classic'] += 1
        else:
            kex['weak only (SHA-1, 1024 bit)'] += 1
        software[_software(banner)] += 1

    return [
        ('Active host keys', donut([(label, types[label], color) for label, color in type_colors.items()])),
        ('Best key exchange offered', donut([
            ('post-quantum', kex['post-quantum'], 'green'),
            ('classic', kex['classic'], 'orange'),
            ('weak only (SHA-1, 1024 bit)', kex['weak only (SHA-1, 1024 bit)'], 'red'),
        ])),
        ('SSH software', donut(top_n(software))),
    ]
