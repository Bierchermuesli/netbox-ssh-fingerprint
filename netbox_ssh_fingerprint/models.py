from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from netbox.context import current_request
from netbox.models import PrimaryModel
from netbox.plugins import get_plugin_config

from .choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices, KeyTypeChoices
from .keys import InvalidKeyError, is_weak, parse_public_key
from .policy import assess

APPROVE_PERMISSION = 'netbox_ssh_fingerprint.approve_hostkey'
FETCH_PERMISSION = 'netbox_ssh_fingerprint.fetch_hostkey'


class HostKey(PrimaryModel):
    """
    One SSH host key of a device or virtual machine. The endpoint tells whether the key belongs to the
    host itself or to its out-of-band interface (BMC, console server), which runs its own SSH server.
    """
    device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.CASCADE,
        related_name='ssh_host_keys',
        blank=True,
        null=True,
    )
    virtual_machine = models.ForeignKey(
        to='virtualization.VirtualMachine',
        on_delete=models.CASCADE,
        related_name='ssh_host_keys',
        blank=True,
        null=True,
    )
    endpoint = models.CharField(
        max_length=10,
        choices=HostKeyEndpointChoices,
        default=HostKeyEndpointChoices.HOST,
    )
    key_type = models.CharField(
        max_length=30,
        choices=KeyTypeChoices,
        editable=False,
    )
    public_key = models.TextField(
        help_text=_('The public key, e.g. the content of /etc/ssh/ssh_host_ed25519_key.pub'),
    )
    fingerprint_sha256 = models.CharField(
        max_length=60,
        editable=False,
        verbose_name=_('Fingerprint (SHA256)'),
    )
    bits = models.PositiveIntegerField(
        editable=False,
        default=0,
    )
    status = models.CharField(
        max_length=20,
        choices=HostKeyStatusChoices,
        default=HostKeyStatusChoices.PENDING,
    )
    source = models.CharField(
        max_length=20,
        choices=HostKeySourceChoices,
        default=HostKeySourceChoices.MANUAL,
    )
    shared = models.BooleanField(
        default=False,
        help_text=_('The same key is legitimately used by several hosts (HA pair, VIP, stack)'),
    )
    last_seen = models.DateTimeField(
        blank=True,
        null=True,
        editable=False,
        help_text=_('When a scan last saw this key on the host'),
    )

    clone_fields = ('device', 'virtual_machine', 'endpoint', 'status', 'source', 'shared')

    class Meta:
        ordering = ('device', 'virtual_machine', 'endpoint', 'key_type', 'pk')
        verbose_name = _('host key')
        verbose_name_plural = _('host keys')
        permissions = [
            ('approve', 'Approve host keys'),
            ('fetch', 'Fetch and verify host keys'),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    Q(device__isnull=False, virtual_machine__isnull=True)
                    | Q(device__isnull=True, virtual_machine__isnull=False)
                ),
                name='%(app_label)s_%(class)s_one_host',
                violation_error_message=_('A host key belongs to either a device or a virtual machine.'),
            ),
            models.UniqueConstraint(
                fields=('device', 'endpoint', 'fingerprint_sha256'),
                condition=Q(device__isnull=False),
                name='%(app_label)s_%(class)s_unique_device_key',
                violation_error_message=_('This key is already recorded for this device.'),
            ),
            models.UniqueConstraint(
                fields=('virtual_machine', 'endpoint', 'fingerprint_sha256'),
                condition=Q(virtual_machine__isnull=False),
                name='%(app_label)s_%(class)s_unique_vm_key',
                violation_error_message=_('This key is already recorded for this virtual machine.'),
            ),
            models.UniqueConstraint(
                fields=('device', 'endpoint', 'key_type'),
                condition=Q(device__isnull=False, status=HostKeyStatusChoices.ACTIVE),
                name='%(app_label)s_%(class)s_one_active_per_type_device',
                violation_error_message=_('The device already has an active key of this type. Revoke it first.'),
            ),
            models.UniqueConstraint(
                fields=('virtual_machine', 'endpoint', 'key_type'),
                condition=Q(virtual_machine__isnull=False, status=HostKeyStatusChoices.ACTIVE),
                name='%(app_label)s_%(class)s_one_active_per_type_vm',
                violation_error_message=_('The VM already has an active key of this type. Revoke it first.'),
            ),
        ]
        indexes = [
            models.Index(fields=('fingerprint_sha256',)),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_status = self.__dict__.get('status')

    def __str__(self):
        return f'{self.host} {self.key_type}' + (' (OOB)' if self.endpoint == HostKeyEndpointChoices.OOB else '')

    @property
    def host(self):
        return self.device or self.virtual_machine

    @property
    def parent_object(self):
        return self.host

    @property
    def weak(self):
        return is_weak(self.key_type, self.bits)

    def get_status_color(self):
        return HostKeyStatusChoices.colors.get(self.status)

    def host_filter(self):
        if self.device_id:
            return Q(device_id=self.device_id)
        return Q(virtual_machine_id=self.virtual_machine_id)

    def same_slot(self):
        """
        Other keys of the same host, endpoint and key type.
        """
        return HostKey.objects.filter(
            self.host_filter(), endpoint=self.endpoint, key_type=self.key_type,
        ).exclude(pk=self.pk)

    def update_derived(self):
        key = parse_public_key(self.public_key)
        self.public_key = key.b64
        self.key_type = key.key_type
        self.fingerprint_sha256 = key.fingerprint_sha256
        self.bits = key.bits
        if key.comment and not self.description:
            self.description = key.comment[:200]

    def auto_accept_allowed(self):
        """
        A host that is still being set up gets its first key of each type without approval.
        """
        host = self.host
        statuses = get_plugin_config('netbox_ssh_fingerprint', 'auto_accept_statuses')
        if host is None or host.status not in statuses:
            return False
        return not self.same_slot().filter(status=HostKeyStatusChoices.ACTIVE).exists()

    def clean(self):
        super().clean()

        if bool(self.device_id) == bool(self.virtual_machine_id):
            raise ValidationError(_('Assign the key to either a device or a virtual machine.'))
        if self.endpoint == HostKeyEndpointChoices.OOB and not self.device_id:
            raise ValidationError({'endpoint': _('Only devices have an out-of-band endpoint.')})

        try:
            self.update_derived()
        except InvalidKeyError as e:
            raise ValidationError({'public_key': str(e)})

        if self.status != HostKeyStatusChoices.ACTIVE:
            return

        if self.same_slot().filter(status=HostKeyStatusChoices.ACTIVE).exists():
            raise ValidationError({
                'status': _('The host already has an active {key_type} key. Approve the new key to replace it, '
                            'or revoke the current one first.').format(key_type=self.key_type),
            })

        # Activating a key needs the approve permission, unless the host is still being set up
        newly_active = self._state.adding or self._original_status != HostKeyStatusChoices.ACTIVE
        request = current_request.get()
        if newly_active and request is not None and not request.user.has_perm(APPROVE_PERMISSION):
            if not self.auto_accept_allowed():
                raise ValidationError({
                    'status': _('Activating a host key requires the approve permission. Save it as pending.'),
                })

        # The same key on several hosts is only allowed when all of them mark it as shared
        others = HostKey.objects.filter(
            fingerprint_sha256=self.fingerprint_sha256, status=HostKeyStatusChoices.ACTIVE,
        ).exclude(pk=self.pk).exclude(self.host_filter())
        if others.exists() and (not self.shared or others.filter(shared=False).exists()):
            names = ', '.join(sorted({str(k.host) for k in others[:5]}))
            raise ValidationError({
                'shared': _('The same key is active on {names}. Mark it as shared on all hosts if this is '
                            'intended (HA pair, VIP), otherwise this is likely a cloned image.').format(names=names),
            })

    def save(self, *args, **kwargs):
        self.update_derived()
        super().save(*args, **kwargs)
        self._original_status = self.status


def _names():
    return ArrayField(models.CharField(max_length=100), default=list, blank=True)


class EndpointScan(models.Model):
    """
    The latest scan of a host's SSH endpoint: reachability, software banner and the algorithms the server
    offers. Overwritten on every scan and kept out of the changelog; key changes are logged on HostKey.
    """
    device = models.ForeignKey(
        to='dcim.Device', on_delete=models.CASCADE, related_name='ssh_endpoint_scans', blank=True, null=True,
    )
    virtual_machine = models.ForeignKey(
        to='virtualization.VirtualMachine', on_delete=models.CASCADE, related_name='ssh_endpoint_scans',
        blank=True, null=True,
    )
    endpoint = models.CharField(max_length=10, choices=HostKeyEndpointChoices, default=HostKeyEndpointChoices.HOST)
    address = models.CharField(max_length=64, blank=True)
    port = models.PositiveIntegerField(default=22)
    scanned_at = models.DateTimeField()
    reachable = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    banner = models.CharField(max_length=255, blank=True)
    kex = _names()
    host_key_algorithms = _names()
    ciphers = _names()
    macs = _names()
    pq_ready = models.BooleanField(default=False)
    weak_algorithms = _names()

    class Meta:
        ordering = ('device', 'virtual_machine', 'endpoint')
        verbose_name = _('endpoint scan')
        constraints = [
            models.UniqueConstraint(
                fields=('device', 'endpoint'), condition=Q(device__isnull=False),
                name='%(app_label)s_%(class)s_unique_device',
            ),
            models.UniqueConstraint(
                fields=('virtual_machine', 'endpoint'), condition=Q(virtual_machine__isnull=False),
                name='%(app_label)s_%(class)s_unique_vm',
            ),
        ]

    def __str__(self):
        return f'{self.device or self.virtual_machine} {self.endpoint} scan'

    @property
    def host(self):
        return self.device or self.virtual_machine

    def update_assessment(self):
        result = assess(self.kex, self.host_key_algorithms, self.ciphers, self.macs)
        self.pq_ready = result.pq_ready
        self.weak_algorithms = result.weak_list

    @property
    def kex_display(self):
        return [k for k in self.kex if not k.startswith(('ext-info-', 'kex-strict-'))]
