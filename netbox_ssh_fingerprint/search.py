from netbox.search import SearchIndex

from .models import HostKey


class HostKeyIndex(SearchIndex):
    model = HostKey
    fields = (
        ('fingerprint_sha256', 100),
        ('description', 500),
        ('comments', 5000),
    )
    display_attrs = ('device', 'virtual_machine', 'key_type', 'status')


indexes = [HostKeyIndex]
