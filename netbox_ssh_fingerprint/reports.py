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

LIMIT = 50


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
