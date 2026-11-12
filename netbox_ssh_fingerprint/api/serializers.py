from rest_framework import serializers

from dcim.api.serializers import DeviceSerializer
from netbox.api.fields import ChoiceField
from netbox.api.serializers import PrimaryModelSerializer
from virtualization.api.serializers import VirtualMachineSerializer

from ..choices import HostKeyEndpointChoices, HostKeySourceChoices, HostKeyStatusChoices
from ..models import EndpointScan, HostKey


class HostKeySerializer(PrimaryModelSerializer):
    device = DeviceSerializer(nested=True, required=False, allow_null=True)
    virtual_machine = VirtualMachineSerializer(nested=True, required=False, allow_null=True)
    endpoint = ChoiceField(choices=HostKeyEndpointChoices, required=False)
    status = ChoiceField(choices=HostKeyStatusChoices, required=False)
    source = ChoiceField(choices=HostKeySourceChoices, required=False)
    weak = serializers.BooleanField(read_only=True)

    class Meta:
        model = HostKey
        fields = (
            'id', 'url', 'display_url', 'display', 'device', 'virtual_machine', 'endpoint', 'key_type', 'public_key',
            'fingerprint_sha256', 'bits', 'weak', 'status', 'source', 'shared', 'last_seen', 'description',
            'owner', 'comments', 'tags', 'custom_fields', 'created', 'last_updated',
        )
        read_only_fields = ('key_type', 'fingerprint_sha256', 'bits', 'last_seen')
        brief_fields = ('id', 'url', 'display', 'key_type', 'fingerprint_sha256', 'status')


class EndpointScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndpointScan
        fields = (
            'endpoint', 'address', 'port', 'scanned_at', 'reachable', 'error', 'banner', 'kex',
            'host_key_algorithms', 'ciphers', 'macs', 'pq_ready', 'weak_algorithms',
        )
