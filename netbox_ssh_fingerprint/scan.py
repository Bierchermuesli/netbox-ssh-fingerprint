"""
Fetch the host keys of a device or VM, compare them with the stored keys and record the result.
"""
from dataclasses import dataclass, field

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.utils import timezone

from dcim.models import Device
from netbox.plugins import get_plugin_config

from .choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices
from .exports import ssh_ports
from .keys import canonical_ip
from .models import EndpointScan, HostKey
from .probe import probe


@dataclass
class EndpointResult:
    endpoint: str
    address: str = ''
    reachable: bool = False
    error: str = ''
    matched: list = field(default_factory=list)       # active keys the host presented
    new_active: list = field(default_factory=list)    # accepted automatically (host is being set up)
    new_pending: list = field(default_factory=list)   # waiting for approval, no active key of that type yet
    mismatched: list = field(default_factory=list)    # differs from the active key of that type
    revoked_seen: list = field(default_factory=list)  # the host presented a revoked key


def host_field(host):
    return 'device' if isinstance(host, Device) else 'virtual_machine'


def endpoints(host):
    """
    (endpoint, [addresses to try]) for each SSH endpoint the host has in NetBox.
    """
    result = []
    addresses = [ip for ip in (host.primary_ip4, host.primary_ip6) if ip]
    if addresses:
        result.append((HostKeyEndpointChoices.HOST, addresses))
    if getattr(host, 'oob_ip', None):
        result.append((HostKeyEndpointChoices.OOB, [host.oob_ip]))
    return result


def record_keys(host, endpoint, keys, now=None):
    """
    Store what a scan found. Known keys get last_seen (without a changelog entry). New keys are
    accepted automatically only while the host is being set up; otherwise they wait for approval.
    """
    now = now or timezone.now()
    out = EndpointResult(endpoint=endpoint)
    hfield = host_field(host)
    for key in keys:
        existing = HostKey.objects.filter(
            **{hfield: host}, endpoint=endpoint, fingerprint_sha256=key.fingerprint_sha256,
        ).first()
        if existing:
            HostKey.objects.filter(pk=existing.pk).update(last_seen=now)
            if existing.status == HostKeyStatusChoices.REVOKED:
                out.revoked_seen.append(existing)
            elif existing.status == HostKeyStatusChoices.ACTIVE:
                out.matched.append(existing)
            elif existing.same_slot().filter(status=HostKeyStatusChoices.ACTIVE).exists():
                out.mismatched.append(existing)
            else:
                out.new_pending.append(existing)
            continue

        new = HostKey(
            **{hfield: host}, endpoint=endpoint, public_key=key.b64,
            source=HostKeySourceChoices.SCAN, status=HostKeyStatusChoices.PENDING, last_seen=now,
        )
        new.update_derived()
        if new.auto_accept_allowed():
            new.status = HostKeyStatusChoices.ACTIVE
            try:
                new.full_clean()
            except ValidationError:
                new.status = HostKeyStatusChoices.PENDING  # e.g. the same key is active elsewhere
        new.full_clean()
        new.save()
        if new.status == HostKeyStatusChoices.ACTIVE:
            out.new_active.append(new)
        elif new.same_slot().filter(status=HostKeyStatusChoices.ACTIVE).exists():
            out.mismatched.append(new)
        else:
            out.new_pending.append(new)
    return out


def record_probe(host, endpoint, result, now=None):
    now = now or timezone.now()
    scan, _ = EndpointScan.objects.get_or_create(
        **{host_field(host): host}, endpoint=endpoint, defaults={'scanned_at': now},
    )
    scan.scanned_at = now
    scan.address = result.address
    scan.port = result.port
    scan.reachable = result.reachable
    scan.error = '\n'.join(result.errors)
    if result.reachable:
        scan.banner = result.banner[:255]
        scan.kex = result.offer.kex
        scan.host_key_algorithms = result.offer.host_key_algorithms
        scan.ciphers = result.offer.ciphers
        scan.macs = result.offer.macs
        scan.update_assessment()
    scan.save()


def scan_host(host, logger=None, prober=probe):
    """
    Probe each endpoint of the host (the first reachable address wins) and record keys and algorithms.
    """
    timeout = get_plugin_config('netbox_ssh_fingerprint', 'fetch_timeout')
    ct = ContentType.objects.get_for_model(host)
    results = []
    for endpoint, addresses in endpoints(host):
        port = 22
        if endpoint == HostKeyEndpointChoices.HOST:
            port = ssh_ports([host]).get((ct.pk, host.pk), 22)
        result = None
        for ip in addresses:
            result = prober(canonical_ip(ip.address), port, timeout)
            if result.reachable:
                break
        now = timezone.now()
        record_probe(host, endpoint, result, now)
        if result.reachable:
            out = record_keys(host, endpoint, result.keys, now)
        else:
            out = EndpointResult(endpoint=endpoint)
        out.address, out.reachable, out.error = result.address, result.reachable, '; '.join(result.errors)
        results.append(out)
        if logger:
            _log(logger, host, out)
    if not results and logger:
        logger.warning(f'{host}: no primary or out-of-band IP, nothing to scan')
    return results


def _log(logger, host, out):
    label = f'{host} ({out.endpoint}, {out.address})'
    if not out.reachable:
        logger.warning(f'{label}: not reachable: {out.error}')
        return
    for key in out.matched:
        logger.info(f'{label}: {key.key_type} matches')
    for key in out.new_active:
        logger.info(f'{label}: {key.key_type} recorded and accepted (host is being set up)')
    for key in out.new_pending:
        logger.warning(f'{label}: new {key.key_type} key waits for approval')
    for key in out.mismatched:
        logger.error(f'{label}: {key.key_type} does NOT match the active key; new key waits for approval')
    for key in out.revoked_seen:
        logger.error(f'{label}: host presents the REVOKED {key.key_type} key {key.fingerprint_sha256}')
    if out.error:
        logger.warning(f'{label}: {out.error}')


def summary(host, out):
    """
    One line per endpoint for the UI: (level, text) with level success, info, warning or error.
    """
    where = 'OOB' if out.endpoint == HostKeyEndpointChoices.OOB else 'SSH'
    label = f'{host} {where} ({out.address})'
    if not out.reachable:
        return 'error', f'{label}: not reachable. {out.error}'
    if out.revoked_seen:
        return 'error', f'{label}: presents a REVOKED key ({", ".join(k.key_type for k in out.revoked_seen)})'
    if out.mismatched:
        return 'error', f'{label}: key differs from the active one ({", ".join(k.key_type for k in out.mismatched)}); ' \
                        f'the new key waits for approval'
    parts = []
    if out.matched:
        parts.append(f'{len(out.matched)} key(s) match')
    if out.new_active:
        parts.append(f'{len(out.new_active)} recorded and accepted (host is being set up)')
    if out.new_pending:
        parts.append(f'{len(out.new_pending)} new, waiting for approval')
    level = 'warning' if out.new_pending else 'success'
    return level, f'{label}: ' + (', '.join(parts) or 'no keys')
