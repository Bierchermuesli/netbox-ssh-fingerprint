import django_tables2 as tables
from django.utils.translation import gettext_lazy as _

from netbox.tables import PrimaryModelTable, columns

from .models import HostKey

FINGERPRINT = '<a href="{{ record.get_absolute_url }}" class="font-monospace">{{ value }}</a>'
WEAK = '{% if record.weak %}<span class="badge text-bg-red">weak</span>{% endif %}'


class HostKeyTable(PrimaryModelTable):
    host = tables.Column(accessor='host', linkify=True, orderable=False, verbose_name=_('Host'))
    device = tables.Column(linkify=True, verbose_name=_('Device'))
    virtual_machine = tables.Column(linkify=True, verbose_name=_('Virtual machine'))
    endpoint = columns.ChoiceFieldColumn(verbose_name=_('Endpoint'))
    key_type = tables.Column(verbose_name=_('Type'))
    bits = tables.Column(verbose_name=_('Bits'))
    weak = columns.TemplateColumn(template_code=WEAK, orderable=False, verbose_name=_('Weak'))
    fingerprint_sha256 = columns.TemplateColumn(template_code=FINGERPRINT, verbose_name=_('Fingerprint'))
    status = columns.ChoiceFieldColumn(verbose_name=_('Status'))
    source = columns.ChoiceFieldColumn(verbose_name=_('Source'))
    shared = columns.BooleanColumn(verbose_name=_('Shared'))
    last_seen = columns.DateTimeColumn(verbose_name=_('Last seen'))
    tags = columns.TagColumn(url_name='plugins:netbox_ssh_fingerprint:hostkey_list')

    class Meta(PrimaryModelTable.Meta):
        model = HostKey
        fields = (
            'pk', 'id', 'host', 'device', 'virtual_machine', 'endpoint', 'key_type', 'bits', 'weak',
            'fingerprint_sha256', 'status', 'source', 'shared', 'last_seen', 'description', 'tags',
            'created', 'last_updated',
        )
        default_columns = (
            'pk', 'host', 'endpoint', 'key_type', 'bits', 'weak', 'fingerprint_sha256', 'status', 'last_seen',
        )
