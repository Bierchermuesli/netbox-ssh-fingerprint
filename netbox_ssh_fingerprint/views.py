import hashlib

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpResponse, HttpResponseNotModified
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views import View

from dcim.models import Device
from extras.ui.panels import CustomFieldsPanel, TagsPanel
from netbox.ui import attrs, layout, panels
from netbox.views import generic
from utilities.views import register_model_view
from virtualization.models import VirtualMachine

from . import actions, exports, filtersets, forms, reports, tables
from .scan import summary
from .models import HostKey

HOST_MODELS = {'device': Device, 'virtualmachine': VirtualMachine}


class HostKeyPanel(panels.ObjectAttributesPanel):
    host = attrs.RelatedObjectAttr('host', linkify=True, label=_('Host'))
    endpoint = attrs.ChoiceAttr('endpoint', label=_('Endpoint'))
    key_type = attrs.TextAttr('key_type', label=_('Type'))
    bits = attrs.NumericAttr('bits', label=_('Bits'))
    fingerprint_sha256 = attrs.TextAttr(
        'fingerprint_sha256', label=_('Fingerprint'), style='font-monospace', copy_button=True,
    )
    status = attrs.ChoiceAttr('status', label=_('Status'))
    source = attrs.ChoiceAttr('source', label=_('Source'))
    shared = attrs.BooleanAttr('shared', label=_('Shared'))
    last_seen = attrs.DateTimeAttr('last_seen', label=_('Last seen'))
    description = attrs.TextAttr('description', label=_('Description'))


#
# Host keys
#

@register_model_view(HostKey, 'list', path='', detail=False)
class HostKeyListView(generic.ObjectListView):
    queryset = HostKey.objects.select_related('device', 'virtual_machine')
    filterset = filtersets.HostKeyFilterSet
    filterset_form = forms.HostKeyFilterForm
    table = tables.HostKeyTable
    template_name = 'netbox_ssh_fingerprint/hostkey_list.html'


@register_model_view(HostKey)
class HostKeyView(generic.ObjectView):
    queryset = HostKey.objects.select_related('device', 'virtual_machine')
    template_name = 'generic/object.html'
    layout = layout.SimpleLayout(
        left_panels=[
            HostKeyPanel(),
            TagsPanel(),
            CustomFieldsPanel(),
        ],
        right_panels=[
            panels.TemplatePanel('netbox_ssh_fingerprint/panels/hostkey_material.html', title=_('Key')),
            panels.CommentsPanel(),
        ],
    )

    def get_extra_context(self, request, instance):
        return {
            'known_hosts': exports.known_hosts(HostKey.objects.filter(pk=instance.pk)),
            'sshfp': exports.sshfp_zone(HostKey.objects.filter(pk=instance.pk)),
            'can_approve': request.user.has_perm('netbox_ssh_fingerprint.approve_hostkey'),
            'can_change': request.user.has_perm('netbox_ssh_fingerprint.change_hostkey'),
        }


@register_model_view(HostKey, 'add', detail=False)
@register_model_view(HostKey, 'edit')
class HostKeyEditView(generic.ObjectEditView):
    queryset = HostKey.objects.all()
    form = forms.HostKeyForm

    def alter_object(self, obj, request, url_args, url_kwargs):
        # Prefill the host when adding from a device or VM page
        if not obj.pk:
            if 'device' in request.GET:
                obj.device = Device.objects.filter(pk=request.GET['device']).first()
            if 'virtual_machine' in request.GET:
                obj.virtual_machine = VirtualMachine.objects.filter(pk=request.GET['virtual_machine']).first()
        return obj


@register_model_view(HostKey, 'delete')
class HostKeyDeleteView(generic.ObjectDeleteView):
    queryset = HostKey.objects.all()


@register_model_view(HostKey, 'bulk_import', path='import', detail=False)
class HostKeyBulkImportView(generic.BulkImportView):
    queryset = HostKey.objects.all()
    model_form = forms.HostKeyImportForm


@register_model_view(HostKey, 'bulk_edit', path='edit', detail=False)
class HostKeyBulkEditView(generic.BulkEditView):
    queryset = HostKey.objects.all()
    filterset = filtersets.HostKeyFilterSet
    table = tables.HostKeyTable
    form = forms.HostKeyBulkEditForm


@register_model_view(HostKey, 'bulk_delete', path='delete', detail=False)
class HostKeyBulkDeleteView(generic.BulkDeleteView):
    queryset = HostKey.objects.all()
    filterset = filtersets.HostKeyFilterSet
    table = tables.HostKeyTable


def _post_action(request, func, success):
    try:
        result = func()
    except PermissionDenied as e:
        messages.error(request, str(e))
        return None
    except ValidationError as e:
        messages.error(request, '; '.join(e.messages))
        return None
    messages.success(request, success(result))
    return result


@register_model_view(HostKey, 'approve')
class HostKeyApproveView(LoginRequiredMixin, View):
    def post(self, request, pk):
        key = get_object_or_404(HostKey.objects.restrict(request.user, 'view'), pk=pk)
        _post_action(request, lambda: actions.approve(key, request.user), lambda r: (
            f'Approved {key.key_type} key' + (f', revoked {len(r[1])} previous key(s)' if r[1] else '')))
        return redirect(key.get_absolute_url())


@register_model_view(HostKey, 'revoke')
class HostKeyRevokeView(LoginRequiredMixin, View):
    def post(self, request, pk):
        key = get_object_or_404(HostKey.objects.restrict(request.user, 'view'), pk=pk)
        _post_action(request, lambda: actions.revoke(key, request.user), lambda r: f'Revoked {key.key_type} key')
        return redirect(key.get_absolute_url())


#
# Actions on devices and VMs
#

def _get_host(request, model, pk):
    if model not in HOST_MODELS:
        raise Http404
    return get_object_or_404(HOST_MODELS[model].objects.restrict(request.user, 'view'), pk=pk)


def _fetch_and_report(request, host):
    """
    Fetch synchronously and show one message per endpoint; changes are logged under the user.
    """
    try:
        results = actions.fetch_now(host, request.user)
    except PermissionDenied as e:
        messages.error(request, str(e))
        return
    if not results:
        messages.warning(request, f'{host} has no primary or out-of-band IP to connect to.')
    for out in results:
        level, text = summary(host, out)
        getattr(messages, level)(request, text)


class FetchView(LoginRequiredMixin, View):
    """
    Fetch the host's keys, compare them with the stored ones and return to the host page.
    """
    def post(self, request, model, pk):
        host = _get_host(request, model, pk)
        _fetch_and_report(request, host)
        return redirect(host.get_absolute_url())


class ReplaceHardwareView(LoginRequiredMixin, View):
    """
    RMA or re-install: revoke the host's active keys, then fetch the new ones.
    """
    def post(self, request, model, pk):
        host = _get_host(request, model, pk)
        revoked = _post_action(request, lambda: actions.replace_hardware(host, request.user),
                               lambda keys: f'Revoked {len(keys)} key(s) of {host}')
        if revoked is not None and actions.can_fetch(request.user):
            _fetch_and_report(request, host)
        return redirect(host.get_absolute_url())


#
# Exports and reports
#

def text_response(request, content, filename):
    etag = '"' + hashlib.sha256(content.encode()).hexdigest()[:32] + '"'
    if etag in request.headers.get('If-None-Match', ''):
        return HttpResponseNotModified()
    response = HttpResponse(content, content_type='text/plain; charset=utf-8')
    response['ETag'] = etag
    if request.GET.get('download'):
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def filtered_keys(request):
    queryset = HostKey.objects.restrict(request.user, 'view')
    params = request.GET.copy()
    for option in ('include', 'hashed', 'revoked', 'download'):
        params.pop(option, None)
    return filtersets.HostKeyFilterSet(params, queryset).qs


def _flag(request, name, default):
    value = request.GET.get(name, '').lower()
    return default if not value else value in ('1', 'true', 'yes', 'on')


def export_options(request):
    """
    include=both|names|ips, hashed=1, revoked=0 (for Paramiko-based clients).
    """
    include = request.GET.get('include') or exports._config('known_hosts_include')
    if include not in exports.INCLUDE_CHOICES:
        include = 'both'
    return {'include': include, 'hashed': _flag(request, 'hashed', False), 'revoked': _flag(request, 'revoked', True)}


class KnownHostsView(LoginRequiredMixin, View):
    """
    known_hosts for all keys matching the key list filters (?site=…&role=…&host_tag=…),
    with ?include=both|names|ips, ?hashed=1, ?revoked=0 and ?download=1.
    """
    def get(self, request):
        content = exports.known_hosts(filtered_keys(request), **export_options(request))
        return text_response(request, content, 'known_hosts')


class SSHFPView(LoginRequiredMixin, View):
    """
    SSHFP records of the active keys, as a zone file snippet.
    """
    def get(self, request):
        return text_response(request, exports.sshfp_zone(filtered_keys(request)), 'sshfp.zone')


class ReportView(LoginRequiredMixin, View):
    def get(self, request):
        if not request.user.has_perm('netbox_ssh_fingerprint.view_hostkey'):
            raise PermissionDenied
        user = request.user
        stale_days, never_seen, stale_count, stale = reports.stale_keys(user)
        mismatch_count, mismatch_list = reports.mismatches(user)
        weak_count, weak_types, weak_list = reports.weak_keys(user)
        dup_count, dup_rows = reports.duplicates(user)
        return render(request, 'netbox_ssh_fingerprint/report.html', {
            'without_key': reports.hosts_without_key(user),
            'stale_days': stale_days, 'never_seen': never_seen, 'stale_count': stale_count, 'stale': stale,
            'mismatch_count': mismatch_count, 'mismatches': mismatch_list,
            'weak_count': weak_count, 'weak_types': weak_types, 'weak_keys': weak_list,
            'dup_count': dup_count, 'duplicates': dup_rows,
            'alg': reports.algorithms(user),
        })
