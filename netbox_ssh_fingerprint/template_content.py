from django.contrib.contenttypes.models import ContentType

from netbox.plugins import PluginTemplateExtension

from .actions import can_fetch
from .choices import HostKeyEndpointChoices, HostKeyStatusChoices
from .exports import ssh_ports
from .keys import canonical_ip
from .models import EndpointScan, HostKey
from .scan import endpoints
from .scope import in_scope


def keyscan_commands(host, active):
    """
    ssh-keyscan commands for the endpoints without an active key, for hosts NetBox cannot reach:
    a technician runs them and pastes the output as scan results.
    """
    ct = ContentType.objects.get_for_model(host)
    commands = []
    for endpoint, addresses in endpoints(host):
        if active.filter(endpoint=endpoint).exists():
            continue
        port = ssh_ports([host]).get((ct.pk, host.pk), 22) if endpoint == HostKeyEndpointChoices.HOST else 22
        port_arg = f' -p {port}' if port != 22 else ''
        targets = ' '.join(canonical_ip(ip.address) for ip in addresses)
        commands.append((endpoint, f'ssh-keyscan -T 5{port_arg} {targets}'))
    return commands


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
        vc = getattr(host, 'virtual_chassis', None)
        if vc and vc.master_id and vc.master_id != host.pk and not keys.exists():
            # A stack answers SSH as one host; its keys are recorded on the master
            return self.render('netbox_ssh_fingerprint/vc_member_card.html', {'vc': vc})
        if not in_scope(host) and not keys.exists():
            return ''
        active = keys.filter(status=HostKeyStatusChoices.ACTIVE)
        return self.render('netbox_ssh_fingerprint/host_card.html', {
            'keyscan': keyscan_commands(host, active),
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
