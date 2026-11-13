from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied as APIPermissionDenied
from rest_framework.exceptions import ValidationError as APIValidationError
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.views import APIView

from netbox.api.authentication import IsAuthenticatedOrLoginNotRequired
from netbox.api.viewsets import NetBoxModelViewSet

from .. import actions, exports, filtersets, importer
from ..choices import HostKeyStatusChoices
from ..models import EndpointScan, HostKey
from ..views import HOST_MODELS, export_options, filtered_keys
from ..scan import summary
from .serializers import EndpointScanSerializer, HostKeySerializer


class SSHFingerprintRootView(APIRootView):
    def get_view_name(self):
        return 'SSH Fingerprint'


def _run(func):
    try:
        return func()
    except PermissionDenied as e:
        raise APIPermissionDenied(str(e))
    except ValidationError as e:
        raise APIValidationError(e.messages)


class HostKeyViewSet(NetBoxModelViewSet):
    queryset = HostKey.objects.select_related('device', 'virtual_machine')
    serializer_class = HostKeySerializer
    filterset_class = filtersets.HostKeyFilterSet

    @extend_schema(request=None, responses=HostKeySerializer)
    @action(detail=True, methods=['post'])
    def approve(self, request, pk):
        """
        Make this the active key of its type; the previously active key of that type is revoked.
        """
        key, _ = _run(lambda: actions.approve(self.get_object(), request.user))
        return Response(self.get_serializer(key).data)

    @extend_schema(request=OpenApiTypes.OBJECT, responses=OpenApiTypes.OBJECT)
    @action(detail=False, methods=['post'], url_path='approve')
    def bulk_approve(self, request):
        """
        {"ids": [1, 2], "include_mismatches": false}: approve new keys; keys that would replace an
        active key only with include_mismatches.
        """
        keys = list(self.get_queryset().filter(pk__in=request.data.get('ids') or []))
        groups, approved, errors = _run(lambda: actions.bulk_approve(
            keys, request.user, include_mismatches=bool(request.data.get('include_mismatches'))))
        return Response({
            'approved': [k.pk for k in approved],
            'skipped_mismatches': [] if request.data.get('include_mismatches') else [k.pk for k in groups['mismatch']],
            'skipped_conflicts': [k.pk for k in groups['conflict']],
            'not_pending': [k.pk for k in groups['not_pending']],
            'errors': [{'id': k.pk, 'error': e} for k, e in errors],
        })

    @extend_schema(request=None, responses=HostKeySerializer)
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk):
        key = _run(lambda: actions.revoke(self.get_object(), request.user))
        return Response(self.get_serializer(key).data)


def _host(request):
    model = request.data.get('object_type', '').replace('dcim.', '').replace('virtualization.', '')
    if model not in HOST_MODELS:
        raise APIValidationError({'object_type': 'dcim.device or virtualization.virtualmachine'})
    return get_object_or_404(HOST_MODELS[model].objects.restrict(request.user, 'view'),
                             pk=request.data.get('object_id'))


class FetchView(APIView):
    """
    POST {"object_type": "dcim.device", "object_id": 1}: fetch and verify the host's keys right away and
    return the result per endpoint. With "background": true, queue a job instead (202).
    """
    permission_classes = [IsAuthenticatedOrLoginNotRequired]

    @extend_schema(request=OpenApiTypes.OBJECT, responses=OpenApiTypes.OBJECT)
    def post(self, request):
        if not actions.can_fetch(request.user):
            raise APIPermissionDenied('Fetching host keys requires the fetch permission.')
        host = _host(request)
        if request.data.get('background'):
            job = _run(lambda: actions.enqueue_fetch(host, request.user))
            return Response({'job_id': job.pk, 'job_url': request.build_absolute_uri(
                f'/api/core/jobs/{job.pk}/')}, status=status.HTTP_202_ACCEPTED)
        results = _run(lambda: actions.fetch_now(host, request.user))
        return Response([{
            'endpoint': out.endpoint,
            'address': out.address,
            'reachable': out.reachable,
            'error': out.error,
            'summary': summary(host, out)[1],
            **{name: [k.pk for k in getattr(out, name)]
               for name in ('matched', 'new_active', 'new_pending', 'mismatched', 'revoked_seen')},
        } for out in results])


class ImportKnownHostsView(APIView):
    """
    POST {"data": "<known_hosts>", "status": "pending|active", "dry_run": true}: match the lines to
    devices and VMs and import their keys. Returns the counts and the lines without a host in NetBox.
    """
    permission_classes = [IsAuthenticatedOrLoginNotRequired]

    @extend_schema(request=OpenApiTypes.OBJECT, responses=OpenApiTypes.OBJECT)
    def post(self, request):
        if not request.user.has_perm('netbox_ssh_fingerprint.add_hostkey'):
            raise APIPermissionDenied()
        status_ = request.data.get('status', HostKeyStatusChoices.PENDING)
        if status_ not in (HostKeyStatusChoices.ACTIVE, HostKeyStatusChoices.PENDING):
            raise APIValidationError({'status': 'pending or active'})
        plan = importer.plan_import(request.data.get('data', ''), request.user)
        result = {
            'counts': plan.counts,
            'unmatched': [{'line': n, 'hosts': p} for n, p in plan.unmatched],
            'ambiguous': [{'line': n, 'hosts': p, 'matches': m} for n, p, m in plan.ambiguous],
            'errors': [{'line': n, 'error': e} for n, e in plan.errors],
        }
        if not request.data.get('dry_run'):
            created, errors = importer.apply_import(plan, status_)
            result['created'] = [k.pk for k in created]
            result['errors'] += [{'line': n, 'error': e} for n, e in errors]
        return Response(result)


class ScanView(APIView):
    """
    GET ?object_type=dcim.device&object_id=1: the latest scan of each endpoint (algorithms, PQ readiness).
    """
    permission_classes = [IsAuthenticatedOrLoginNotRequired]

    @extend_schema(parameters=[
        OpenApiParameter('object_type', OpenApiTypes.STR, required=True),
        OpenApiParameter('object_id', OpenApiTypes.INT, required=True),
    ], responses=EndpointScanSerializer(many=True))
    def get(self, request):
        model = request.query_params.get('object_type', '').split('.')[-1]
        if model not in HOST_MODELS:
            raise Http404
        host = get_object_or_404(HOST_MODELS[model].objects.restrict(request.user, 'view'),
                                 pk=request.query_params.get('object_id'))
        field = 'device' if model == 'device' else 'virtual_machine'
        return Response(EndpointScanSerializer(EndpointScan.objects.filter(**{field: host}), many=True).data)


class KnownHostsView(APIView):
    """
    known_hosts as text/plain. Takes the host key filters (site, role, tenant, host_tag, …) plus
    include=both|names|ips, hashed=1 and revoked=0 (omit @revoked lines for Paramiko-based clients).
    """
    permission_classes = [IsAuthenticatedOrLoginNotRequired]

    @extend_schema(responses={(200, 'text/plain'): OpenApiTypes.STR})
    def get(self, request):
        if not request.user.has_perm('netbox_ssh_fingerprint.view_hostkey'):
            raise APIPermissionDenied()
        return HttpResponse(exports.known_hosts(filtered_keys(request), **export_options(request)),
                            content_type='text/plain; charset=utf-8')


class SSHFPView(APIView):
    """
    SSHFP records of the active keys as a zone file snippet (text/plain). Takes the host key filters.
    """
    permission_classes = [IsAuthenticatedOrLoginNotRequired]

    @extend_schema(responses={(200, 'text/plain'): OpenApiTypes.STR})
    def get(self, request):
        if not request.user.has_perm('netbox_ssh_fingerprint.view_hostkey'):
            raise APIPermissionDenied()
        return HttpResponse(exports.sshfp_zone(filtered_keys(request)), content_type='text/plain; charset=utf-8')
