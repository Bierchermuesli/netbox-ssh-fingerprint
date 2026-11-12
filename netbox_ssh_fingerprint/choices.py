from django.utils.translation import gettext_lazy as _

from utilities.choices import ChoiceSet

from .keys import KEY_TYPES


class HostKeyStatusChoices(ChoiceSet):
    key = 'HostKey.status'

    PENDING = 'pending'
    ACTIVE = 'active'
    REVOKED = 'revoked'

    CHOICES = [
        (PENDING, _('Pending'), 'yellow'),
        (ACTIVE, _('Active'), 'green'),
        (REVOKED, _('Revoked'), 'red'),
    ]


class HostKeyEndpointChoices(ChoiceSet):
    HOST = 'host'
    OOB = 'oob'

    CHOICES = [
        (HOST, _('Host')),
        (OOB, _('Out-of-band')),
    ]


class HostKeySourceChoices(ChoiceSet):
    MANUAL = 'manual'
    API = 'api'
    SCAN = 'scan'
    IMPORT = 'import'

    CHOICES = [
        (MANUAL, _('Manual')),
        (API, _('API')),
        (SCAN, _('Scan')),
        (IMPORT, _('Import')),
    ]


class KeyTypeChoices(ChoiceSet):
    CHOICES = [(t, t) for t in KEY_TYPES]
