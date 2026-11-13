"""
Approve, revoke and fetch: shared by the UI views and the REST API.
"""
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction

from .choices import HostKeyStatusChoices
from .jobs import FetchHostKeysJob
from .models import APPROVE_PERMISSION, FETCH_PERMISSION, HostKey
from .scan import scan_host


def _save(key, status):
    key.snapshot()
    key.status = status
    key.full_clean()
    key.save()


@transaction.atomic
def approve(key, user):
    """
    Make the key the active one of its type. The previously active key of that type is revoked, so a
    host that presents it again is refused (re-install, RMA).
    """
    if not user.has_perm(APPROVE_PERMISSION):
        raise PermissionDenied('Approving host keys requires the approve permission.')
    replaced = []
    for old in key.same_slot().filter(status=HostKeyStatusChoices.ACTIVE).select_for_update(of=('self',)):
        _save(old, HostKeyStatusChoices.REVOKED)
        replaced.append(old)
    key = HostKey.objects.select_for_update(of=('self',)).get(pk=key.pk)
    _save(key, HostKeyStatusChoices.ACTIVE)
    return key, replaced


def classify_for_approval(keys):
    """
    Sort keys for a bulk approval: new (no active key of that type yet), mismatch (would replace an
    active key), conflict (several selected keys for the same host, endpoint and type) and not_pending.
    """
    groups = {'new': [], 'mismatch': [], 'conflict': [], 'not_pending': []}
    pending = [k for k in keys if k.status == HostKeyStatusChoices.PENDING]
    groups['not_pending'] = [k for k in keys if k.status != HostKeyStatusChoices.PENDING]
    slots = {}
    for key in pending:
        slots.setdefault((key.device_id, key.virtual_machine_id, key.endpoint, key.key_type), []).append(key)
    for selected in slots.values():
        if len(selected) > 1:
            groups['conflict'] += selected
        elif selected[0].same_slot().filter(status=HostKeyStatusChoices.ACTIVE).exists():
            groups['mismatch'].append(selected[0])
        else:
            groups['new'].append(selected[0])
    return groups


def bulk_approve(keys, user, include_mismatches=False):
    """
    Approve new keys; keys that replace an active one only with include_mismatches. Each key is
    approved on its own, so one failure (e.g. the same key active on another host) does not stop the rest.
    Returns (groups, approved, errors).
    """
    if not user.has_perm(APPROVE_PERMISSION):
        raise PermissionDenied('Approving host keys requires the approve permission.')
    groups = classify_for_approval(keys)
    approved, errors = [], []
    for key in groups['new'] + (groups['mismatch'] if include_mismatches else []):
        try:
            approved.append(approve(key, user)[0])
        except ValidationError as e:
            errors.append((key, '; '.join(e.messages)))
    return groups, approved, errors


@transaction.atomic
def revoke(key, user):
    if not user.has_perm('netbox_ssh_fingerprint.change_hostkey'):
        raise PermissionDenied('Revoking host keys requires the change permission.')
    _save(key, HostKeyStatusChoices.REVOKED)
    return key


@transaction.atomic
def replace_hardware(host, user):
    """
    RMA or re-install: revoke all active keys of the host. A following scan records the new keys as
    pending; they need approval unless the host is in a setup status (planned, staged).
    """
    if not user.has_perm('netbox_ssh_fingerprint.change_hostkey'):
        raise PermissionDenied('Revoking host keys requires the change permission.')
    keys = list(host.ssh_host_keys.filter(status=HostKeyStatusChoices.ACTIVE))
    for key in keys:
        _save(key, HostKeyStatusChoices.REVOKED)
    return keys


def can_fetch(user):
    return user.has_perm(FETCH_PERMISSION)


def fetch_now(host, user):
    """
    Fetch and verify in the current request. A reachable host takes well under a second; an unreachable
    one up to fetch_timeout per address.
    """
    if not can_fetch(user):
        raise PermissionDenied('Fetching host keys requires the fetch permission.')
    return scan_host(host)


def enqueue_fetch(host, user):
    if not can_fetch(user):
        raise PermissionDenied('Fetching host keys requires the fetch permission.')
    return FetchHostKeysJob.enqueue_for(host, user)
