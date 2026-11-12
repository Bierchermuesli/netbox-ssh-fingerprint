from netbox.plugins import PluginTemplateExtension

from .actions import can_fetch
from .models import EndpointScan, HostKey
from .scope import in_scope


class HostKeysCard(PluginTemplateExtension):
    """
    On device and VM pages: the host keys, the latest scan and the fetch button.
    """
    models = ['dcim.device', 'virtualization.virtualmachine']

    def right_page(self):
        user = self.context['request'].user
        if not user.has_perm('netbox_ssh_fingerprint.view_hostkey'):
            return ''
        host = self.context['object']
        host_field = 'device' if host._meta.model_name == 'device' else 'virtual_machine'
        keys = HostKey.objects.restrict(user, 'view').filter(**{host_field: host}).order_by(
            'endpoint', 'status', 'key_type')
        if not in_scope(host) and not keys.exists():
            return ''
        return self.render('netbox_ssh_fingerprint/host_card.html', {
            'host': host,
            'host_field': host_field,
            'model_name': host._meta.model_name,
            'keys': keys,
            'scans': EndpointScan.objects.filter(**{host_field: host}).order_by('endpoint'),
            'can_fetch': can_fetch(user),
            'can_add': user.has_perm('netbox_ssh_fingerprint.add_hostkey'),
            'can_change': user.has_perm('netbox_ssh_fingerprint.change_hostkey'),
        })


template_extensions = [HostKeysCard]
