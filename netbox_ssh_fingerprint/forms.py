from django import forms
from django.utils.translation import gettext_lazy as _

from dcim.models import Device, DeviceRole, Site
from netbox.forms import (
    PrimaryModelBulkEditForm, PrimaryModelFilterSetForm, PrimaryModelForm, PrimaryModelImportForm,
)
from tenancy.models import Tenant
from utilities.forms import BOOLEAN_WITH_BLANK_CHOICES, add_blank_choice
from utilities.forms.fields import (
    CSVChoiceField, CSVModelChoiceField, DynamicModelChoiceField, DynamicModelMultipleChoiceField, TagFilterField,
)
from utilities.forms.rendering import FieldSet, TabbedGroups
from virtualization.models import VirtualMachine

from .choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices, KeyTypeChoices
from .models import HostKey


class HostKeyForm(PrimaryModelForm):
    device = DynamicModelChoiceField(label=_('Device'), queryset=Device.objects.all(), required=False)
    virtual_machine = DynamicModelChoiceField(
        label=_('Virtual machine'), queryset=VirtualMachine.objects.all(), required=False,
    )
    public_key = forms.CharField(
        label=_('Public key'),
        widget=forms.Textarea(attrs={'rows': 3, 'class': 'font-monospace'}),
        help_text=_('"ssh-ed25519 AAAA…", a known_hosts or ssh-keyscan line, or the base64 part alone'),
    )

    fieldsets = (
        FieldSet(
            TabbedGroups(
                FieldSet('device', name=_('Device')),
                FieldSet('virtual_machine', name=_('Virtual machine')),
            ),
            'endpoint', name=_('Host'),
        ),
        FieldSet('public_key', 'status', 'shared', 'source', 'description', 'tags', name=_('Key')),
    )

    class Meta:
        model = HostKey
        fields = (
            'device', 'virtual_machine', 'endpoint', 'public_key', 'status', 'shared', 'source',
            'description', 'owner', 'comments', 'tags',
        )


class HostKeyFilterForm(PrimaryModelFilterSetForm):
    model = HostKey
    fieldsets = (
        FieldSet('q', 'filter_id', 'tag'),
        FieldSet('status', 'key_type', 'endpoint', 'source', 'weak', 'shared', name=_('Key')),
        FieldSet('device_id', 'virtual_machine_id', 'site_id', 'tenant_id', 'role_id', name=_('Host')),
        FieldSet('owner_group_id', 'owner_id', name=_('Ownership')),
    )
    selector_fields = ('filter_id', 'q', 'device_id', 'virtual_machine_id')
    status = forms.MultipleChoiceField(label=_('Status'), choices=HostKeyStatusChoices, required=False)
    key_type = forms.MultipleChoiceField(label=_('Key type'), choices=KeyTypeChoices, required=False)
    endpoint = forms.MultipleChoiceField(label=_('Endpoint'), choices=HostKeyEndpointChoices, required=False)
    source = forms.MultipleChoiceField(label=_('Source'), choices=HostKeySourceChoices, required=False)
    weak = forms.NullBooleanField(
        label=_('Weak'), required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES),
    )
    shared = forms.NullBooleanField(
        label=_('Shared'), required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES),
    )
    device_id = DynamicModelMultipleChoiceField(queryset=Device.objects.all(), required=False, label=_('Device'))
    virtual_machine_id = DynamicModelMultipleChoiceField(
        queryset=VirtualMachine.objects.all(), required=False, label=_('Virtual machine'),
    )
    site_id = DynamicModelMultipleChoiceField(queryset=Site.objects.all(), required=False, label=_('Site'))
    tenant_id = DynamicModelMultipleChoiceField(queryset=Tenant.objects.all(), required=False, label=_('Tenant'))
    role_id = DynamicModelMultipleChoiceField(queryset=DeviceRole.objects.all(), required=False, label=_('Role'))
    tag = TagFilterField(model)


class HostKeyImportForm(PrimaryModelImportForm):
    device = CSVModelChoiceField(
        label=_('Device'), queryset=Device.objects.all(), required=False, to_field_name='name',
    )
    virtual_machine = CSVModelChoiceField(
        label=_('Virtual machine'), queryset=VirtualMachine.objects.all(), required=False, to_field_name='name',
    )
    endpoint = CSVChoiceField(label=_('Endpoint'), choices=HostKeyEndpointChoices, required=False)
    status = CSVChoiceField(label=_('Status'), choices=HostKeyStatusChoices, required=False)
    source = CSVChoiceField(label=_('Source'), choices=HostKeySourceChoices, required=False)

    class Meta:
        model = HostKey
        fields = (
            'device', 'virtual_machine', 'endpoint', 'public_key', 'status', 'shared', 'source',
            'description', 'owner', 'comments', 'tags',
        )


class HostKeyBulkEditForm(PrimaryModelBulkEditForm):
    model = HostKey
    status = forms.ChoiceField(label=_('Status'), choices=add_blank_choice(HostKeyStatusChoices), required=False)
    shared = forms.NullBooleanField(
        label=_('Shared'), required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES),
    )
    description = forms.CharField(label=_('Description'), max_length=200, required=False)

    fieldsets = (
        FieldSet('status', 'shared', 'description'),
    )
    nullable_fields = ('description', 'comments')
