"""
Match known_hosts lines to devices and VMs (by name, DNS name or IP) and record their keys. Two modes:

- import: the migration from an existing tool, whose keys were already trusted (apply_import);
- scan: keys just observed by ssh-keyscan, an Ansible playbook or another collector (apply_observed).
  They are handled like a fetch from NetBox: known keys get last_seen, new ones wait for approval.
"""
from collections import defaultdict
from dataclasses import dataclass, field

from django.core.exceptions import ValidationError
from django.utils import timezone

from dcim.models import Device
from netbox.plugins import get_plugin_config
from virtualization.models import VirtualMachine

from .choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices
from .keys import InvalidKeyError, canonical_ip, parse_public_key
from .models import HostKey
from .scan import record_keys


@dataclass
class Entry:
    lineno: int
    patterns: list
    key: object  # PublicKey
    revoked: bool = False


@dataclass
class Planned:
    entry: Entry
    host: object
    endpoint: str
    category: str  # new, mismatch, existing


@dataclass
class Plan:
    mode: str = 'import'
    items: list = field(default_factory=list)
    unmatched: list = field(default_factory=list)     # (lineno, patterns)
    ambiguous: list = field(default_factory=list)     # (lineno, patterns, [hosts])
    errors: list = field(default_factory=list)        # (lineno, message)

    def by_category(self, category):
        return [i for i in self.items if i.category == category]

    @property
    def counts(self):
        counts = {c: len(self.by_category(c)) for c in ('new', 'mismatch', 'existing')}
        counts.update(unmatched=len(self.unmatched), ambiguous=len(self.ambiguous), errors=len(self.errors))
        return counts


def _host_of_pattern(pattern):
    """
    "[sw1]:2222" -> "sw1"; negations and wildcards cannot be matched to one host.
    """
    if pattern.startswith('!') or '*' in pattern or '?' in pattern:
        return None
    if pattern.startswith('['):
        return pattern[1:].split(']', 1)[0]
    return pattern


def parse_known_hosts(text):
    entries, errors = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        revoked = False
        if line.startswith('@'):
            marker, _, line = line.partition(' ')
            if marker == '@revoked':
                revoked = True
            else:
                errors.append((lineno, f'{marker} lines are not supported'))
                continue
        hosts, _, keypart = line.strip().partition(' ')
        if hosts.startswith('|1|'):
            errors.append((lineno, 'hashed host name cannot be matched; export the file without HashKnownHosts'))
            continue
        try:
            key = parse_public_key(keypart)
        except InvalidKeyError as e:
            errors.append((lineno, str(e)))
            continue
        patterns = [h for h in (_host_of_pattern(p) for p in hosts.split(',')) if h]
        entries.append(Entry(lineno=lineno, patterns=patterns, key=key, revoked=revoked))
    return entries, errors


class HostIndex:
    """
    Names and addresses of all devices and VMs the user can see, mapped to (host, endpoint).
    """
    def __init__(self, user):
        self.map = defaultdict(set)
        suffixes = [s.strip('.') for s in get_plugin_config('netbox_ssh_fingerprint', 'domain_suffixes')]
        devices = Device.objects.restrict(user, 'view').select_related('primary_ip4', 'primary_ip6', 'oob_ip')
        vms = VirtualMachine.objects.restrict(user, 'view').select_related('primary_ip4', 'primary_ip6')
        for host in [*devices, *vms]:
            if host.name:
                self._add(host.name, host, HostKeyEndpointChoices.HOST)
                for suffix in suffixes:
                    self._add(f'{host.name}.{suffix}', host, HostKeyEndpointChoices.HOST)
            for ip in (host.primary_ip4, host.primary_ip6):
                if ip:
                    self._add_ip(ip, host, HostKeyEndpointChoices.HOST)
            if getattr(host, 'oob_ip', None):
                self._add_ip(host.oob_ip, host, HostKeyEndpointChoices.OOB)

    def _add(self, name, host, endpoint):
        self.map[name.lower().rstrip('.')].add((host, endpoint))

    def _add_ip(self, ip, host, endpoint):
        self._add(canonical_ip(ip.address), host, endpoint)
        if ip.dns_name:
            self._add(ip.dns_name, host, endpoint)

    def lookup(self, pattern):
        try:
            pattern = canonical_ip(pattern)
        except ValueError:
            pattern = pattern.lower().rstrip('.')
        return self.map.get(pattern, set())


def _slot(host, endpoint):
    field = 'device' if isinstance(host, Device) else 'virtual_machine'
    return field, host.pk, endpoint


MODES = ('import', 'scan')


def plan_import(text, user, mode='import'):
    """
    In scan mode, @revoked lines are ignored: a scan reports what a host presents, not a verdict.
    """
    entries, errors = parse_known_hosts(text)
    plan = Plan(mode=mode, errors=errors)
    revoked_too = mode == 'import'
    index = HostIndex(user)
    seen = set()            # (slot, fingerprint) already planned
    active_types = set()    # (slot, key type) that will have an active key
    for entry in entries:
        targets = set()
        for pattern in entry.patterns:
            targets |= index.lookup(pattern)
        if not targets:
            plan.unmatched.append((entry.lineno, entry.patterns))
            continue
        if len(targets) > 1:
            plan.ambiguous.append((entry.lineno, entry.patterns, sorted(str(h) for h, _ in targets)))
            continue
        if entry.revoked and not revoked_too:
            continue
        host, endpoint = next(iter(targets))
        slot = _slot(host, endpoint)
        fp = entry.key.fingerprint_sha256
        if (slot, fp) in seen:
            continue  # same key listed again, e.g. once by name and once by IP
        seen.add((slot, fp))
        field, pk, _ = slot
        stored = HostKey.objects.filter(**{f'{field}_id': pk}, endpoint=endpoint)
        if stored.filter(fingerprint_sha256=fp).exists():
            category = 'existing'
        elif not entry.revoked and (
            (slot, entry.key.key_type) in active_types
            or stored.filter(key_type=entry.key.key_type, status=HostKeyStatusChoices.ACTIVE).exists()
        ):
            category = 'mismatch'
        else:
            category = 'new'
            if not entry.revoked:
                active_types.add((slot, entry.key.key_type))
        plan.items.append(Planned(entry=entry, host=host, endpoint=endpoint, category=category))
    return plan


def apply_import(plan, status):
    """
    Create the planned keys. New keys get the requested status (active needs the approve permission),
    keys that would replace an active one stay pending, revoked lines are stored as revoked.
    Returns (created, errors).
    """
    created, errors = [], []
    for item in plan.items:
        if item.category == 'existing':
            continue
        if item.entry.revoked:
            key_status = HostKeyStatusChoices.REVOKED
        elif item.category == 'mismatch':
            key_status = HostKeyStatusChoices.PENDING
        else:
            key_status = status
        field = 'device' if isinstance(item.host, Device) else 'virtual_machine'
        key = HostKey(**{field: item.host}, endpoint=item.endpoint, public_key=item.entry.key.b64,
                      status=key_status, source=HostKeySourceChoices.IMPORT)
        try:
            key.full_clean()
        except ValidationError as e:
            if key_status != HostKeyStatusChoices.ACTIVE:
                errors.append((item.entry.lineno, '; '.join(e.messages)))
                continue
            key.status = HostKeyStatusChoices.PENDING  # e.g. the same key is active on another host
            try:
                key.full_clean()
            except ValidationError as e2:
                errors.append((item.entry.lineno, '; '.join(e2.messages)))
                continue
        key.save()
        created.append(key)
    return created, errors


@dataclass
class ObservedResult:
    host: object
    result: object  # scan.EndpointResult


def apply_observed(plan, now=None):
    """
    Record keys a scan outside NetBox saw, per host and endpoint, like a fetch from NetBox: known keys
    get last_seen, new keys wait for approval (or are accepted while the host is being set up), keys
    that differ from the active one are mismatches.
    """
    now = now or timezone.now()
    groups = defaultdict(list)
    for item in plan.items:
        groups[(item.host, item.endpoint)].append(item.entry.key)
    return [ObservedResult(host=host, result=record_keys(host, endpoint, keys, now))
            for (host, endpoint), keys in groups.items()]


def observed_counts(results):
    counts = dict(refreshed=0, new_active=0, new_pending=0, mismatched=0, revoked_seen=0)
    for r in results:
        counts['refreshed'] += len(r.result.matched)
        counts['new_active'] += len(r.result.new_active)
        counts['new_pending'] += len(r.result.new_pending)
        counts['mismatched'] += len(r.result.mismatched)
        counts['revoked_seen'] += len(r.result.revoked_seen)
    return counts
