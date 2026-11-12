"""
Which devices and VMs are expected to run SSH, from the device_roles and vm_roles settings.
"""
from django.db.models import Q

from dcim.models import Device
from netbox.plugins import get_plugin_config


def _roles(model):
    name = 'device_roles' if model is Device or isinstance(model, Device) else 'vm_roles'
    return get_plugin_config('netbox_ssh_fingerprint', name) or []


def scope_filter(model):
    """
    A Q for the hosts of this model in scope; all hosts when no roles are configured.
    """
    roles = _roles(model)
    return Q(role__slug__in=roles) if roles else Q()


def in_scope(host):
    roles = _roles(host)
    return not roles or (host.role is not None and host.role.slug in roles)
