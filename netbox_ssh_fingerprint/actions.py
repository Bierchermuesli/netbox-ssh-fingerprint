"""
Approve, revoke and fetch: shared by the UI views and the REST API.
"""
from django.core.exceptions import PermissionDenied
from django.db import transaction

from .choices import HostKeyStatusChoices
from .jobs import FetchHostKeysJob
from .models import APPROVE_PERMISSION, FETCH_PERMISSION, HostKey


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


def enqueue_fetch(host, user):
    if not can_fetch(user):
        raise PermissionDenied('Fetching host keys requires the fetch permission.')
    return FetchHostKeysJob.enqueue_for(host, user)
