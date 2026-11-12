import django_filters
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, DeviceRole, Site
from netbox.filtersets import PrimaryModelFilterSet
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from .choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices, KeyTypeChoices
from .models import HostKey


class HostKeyFilterSet(PrimaryModelFilterSet):
    """
    Site, tenant, role and host tag filters match the device or VM a key belongs to.
    """
    device_id = django_filters.ModelMultipleChoiceFilter(queryset=Device.objects.all(), label=_('Device (ID)'))
    device = django_filters.ModelMultipleChoiceFilter(
        field_name='device__name', queryset=Device.objects.all(), to_field_name='name', label=_('Device (name)'),
    )
    virtual_machine_id = django_filters.ModelMultipleChoiceFilter(
        queryset=VirtualMachine.objects.all(), label=_('Virtual machine (ID)'),
    )
    virtual_machine = django_filters.ModelMultipleChoiceFilter(
        field_name='virtual_machine__name', queryset=VirtualMachine.objects.all(), to_field_name='name',
        label=_('Virtual machine (name)'),
    )
    site_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Site.objects.all(), method='filter_host', label=_('Site (ID)'),
    )
    site = django_filters.ModelMultipleChoiceFilter(
        queryset=Site.objects.all(), to_field_name='slug', method='filter_host', label=_('Site (slug)'),
    )
    tenant_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(), method='filter_host', label=_('Tenant (ID)'),
    )
    tenant = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(), to_field_name='slug', method='filter_host', label=_('Tenant (slug)'),
    )
    role_id = django_filters.ModelMultipleChoiceFilter(
        queryset=DeviceRole.objects.all(), method='filter_host', label=_('Device or VM role (ID)'),
    )
    role = django_filters.ModelMultipleChoiceFilter(
        queryset=DeviceRole.objects.all(), to_field_name='slug', method='filter_host',
        label=_('Device or VM role (slug)'),
    )
    host_tag = django_filters.CharFilter(method='filter_host_tag', label=_('Tag of the device or VM (slug)'))
    status = django_filters.MultipleChoiceFilter(choices=HostKeyStatusChoices)
    endpoint = django_filters.MultipleChoiceFilter(choices=HostKeyEndpointChoices)
    source = django_filters.MultipleChoiceFilter(choices=HostKeySourceChoices)
    key_type = django_filters.MultipleChoiceFilter(choices=KeyTypeChoices)
    weak = django_filters.BooleanFilter(method='filter_weak', label=_('Weak key'))

    class Meta:
        model = HostKey
        fields = ('id', 'fingerprint_sha256', 'shared', 'bits', 'last_seen', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(fingerprint_sha256__icontains=value)
            | Q(public_key__contains=value.strip())
            | Q(device__name__icontains=value)
            | Q(virtual_machine__name__icontains=value)
            | Q(description__icontains=value)
        )

    _HOST_FIELDS = {
        'site_id': 'site', 'site': 'site', 'tenant_id': 'tenant', 'tenant': 'tenant',
        'role_id': 'role', 'role': 'role',
    }

    def filter_host(self, queryset, name, value):
        if not value:
            return queryset
        attr = self._HOST_FIELDS[name]
        return queryset.filter(Q(**{f'device__{attr}__in': value}) | Q(**{f'virtual_machine__{attr}__in': value}))

    def filter_host_tag(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(Q(device__tags__slug=value) | Q(virtual_machine__tags__slug=value)).distinct()

    def filter_weak(self, queryset, name, value):
        weak = Q(key_type='ssh-dss') | Q(key_type='ssh-rsa', bits__lt=2048)
        return queryset.filter(weak) if value else queryset.exclude(weak)
