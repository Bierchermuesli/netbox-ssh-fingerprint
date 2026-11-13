from django.urls import reverse_lazy
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

pending = PluginMenuItem(
    link='plugins:netbox_ssh_fingerprint:hostkey_list',
    link_text=_('Pending approval'),
    permissions=['netbox_ssh_fingerprint.view_hostkey'],
)
pending.url = format_lazy('{}?status=pending', reverse_lazy('plugins:netbox_ssh_fingerprint:hostkey_list'))

menu = PluginMenu(
    label=_('SSH Fingerprint'),
    icon_class='mdi mdi-key-chain-variant',
    groups=(
        (_('Host Keys'), (
            PluginMenuItem(
                link='plugins:netbox_ssh_fingerprint:hostkey_list',
                link_text=_('Host Keys'),
                permissions=['netbox_ssh_fingerprint.view_hostkey'],
                buttons=(
                    PluginMenuButton(
                        link='plugins:netbox_ssh_fingerprint:hostkey_add', title=_('Add'),
                        icon_class='mdi mdi-plus-thick', permissions=['netbox_ssh_fingerprint.add_hostkey'],
                    ),
                    PluginMenuButton(
                        link='plugins:netbox_ssh_fingerprint:hostkey_bulk_import', title=_('Import'),
                        icon_class='mdi mdi-upload', permissions=['netbox_ssh_fingerprint.add_hostkey'],
                    ),
                ),
            ),
            pending,
            PluginMenuItem(
                link='plugins:netbox_ssh_fingerprint:report',
                link_text=_('Report'),
                permissions=['netbox_ssh_fingerprint.view_hostkey'],
            ),
        )),
        (_('Export'), (
            PluginMenuItem(
                link='plugins:netbox_ssh_fingerprint:known_hosts',
                link_text=_('known_hosts'),
                permissions=['netbox_ssh_fingerprint.view_hostkey'],
            ),
            PluginMenuItem(
                link='plugins:netbox_ssh_fingerprint:sshfp',
                link_text=_('SSHFP records'),
                permissions=['netbox_ssh_fingerprint.view_hostkey'],
            ),
        )),
    ),
)
