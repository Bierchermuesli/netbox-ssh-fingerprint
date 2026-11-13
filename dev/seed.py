# Demo data: real lab hosts to scan, a local SSH server, and invented hosts in the documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) with keys and scan results covering
# every report case. Rerunning recreates the keys and scans of the invented hosts (tag "ssh-demo");
# keys of the real hosts are kept.
import base64
import random
import struct
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from dcim.models import Device, DeviceRole, DeviceType, Interface, Manufacturer, Site, VirtualChassis
from extras.models import Tag
from ipam.models import FHRPGroup, FHRPGroupAssignment, IPAddress, Service
from tenancy.models import Tenant
from virtualization.models import Cluster, ClusterType, VirtualMachine, VMInterface

from netbox_ssh_fingerprint.models import EndpointScan, HostKey

rng = random.Random(42)
now = timezone.now()


def get(model_cls, **kw):
    defaults = kw.pop('defaults', {})
    return model_cls.objects.get_or_create(**kw, defaults=defaults)[0]


def slug(name):
    return name.lower().replace(' ', '-')


demo_tag = get(Tag, name='ssh-demo', defaults={'slug': 'ssh-demo', 'color': '9e9e9e'})

# Organisation
tenant_net = get(Tenant, name='Network', defaults={'slug': 'network'})
tenant_srv = get(Tenant, name='Server Team', defaults={'slug': 'server-team'})
sites = {name: get(Site, name=name, defaults={'slug': slug(name)}) for name in (
    'Lab', 'RZ Bern', 'RZ Zuerich', 'Filiale Thun')}
roles = {name: get(DeviceRole, name=name, defaults={'slug': slug(name), 'color': color}) for name, color in (
    ('Router', 'f44336'), ('Switch', '2196f3'), ('Firewall', 'ff9800'), ('Server', '4caf50'),
    ('Console Server', '9c27b0'), ('Linux VM', '8bc34a'), ('Access Point', '00bcd4'))}
types = {}
for vendor, model in (('Cisco', 'Catalyst 9300'), ('Cisco', 'Catalyst 2960'), ('Juniper', 'MX204'),
                      ('Arista', 'DCS-7050'), ('Fortinet', 'FortiGate 100F'), ('Dell', 'PowerEdge R650'),
                      ('Opengear', 'CM8100'), ('Generic', 'Linux Router'), ('Cisco', 'C9120AXI')):
    mf = get(Manufacturer, name=vendor, defaults={'slug': slug(vendor)})
    types[model] = get(DeviceType, manufacturer=mf, model=model, defaults={'slug': slug(model)})
ctype = get(ClusterType, name='VMware', defaults={'slug': 'vmware'})
cluster = get(Cluster, name='rz-bern-vsphere', defaults={'type': ctype})


def device(name, model, role, site, status='active', tenant=tenant_net):
    return get(Device, name=name, defaults={
        'device_type': types[model], 'role': roles[role], 'site': sites[site], 'status': status, 'tenant': tenant})


def vm(name, status='active'):
    return get(VirtualMachine, name=name, defaults={
        'cluster': cluster, 'site': sites['RZ Bern'], 'role': roles['Linux VM'], 'status': status,
        'tenant': tenant_srv})


def address(host, ip, dns_name='', oob=False):
    """
    Put an IP on the host's management interface (or its BMC) and make it primary or out-of-band.
    """
    if isinstance(host, Device):
        iface = get(Interface, device=host, name='bmc' if oob else 'mgmt0', defaults={'type': '1000base-t'})
    else:
        iface = get(VMInterface, virtual_machine=host, name='eth0')
    obj = IPAddress.objects.filter(address=ip).first() or IPAddress(address=ip)
    if obj.pk:  # rerun with a changed plan: release the address from whoever had it
        for model, fields in ((Device, ('primary_ip4', 'primary_ip6', 'oob_ip')),
                              (VirtualMachine, ('primary_ip4', 'primary_ip6'))):
            for f in fields:
                model.objects.filter(**{f: obj}).update(**{f: None})
        host.refresh_from_db()
    obj.assigned_object = iface
    obj.dns_name = dns_name
    obj.save()
    if oob:
        host.oob_ip = obj
    elif ':' not in str(ip):
        host.primary_ip4 = obj
    else:
        host.primary_ip6 = obj
    host.save()
    return obj


#
# Real hosts in the lab: no keys, use "Fetch & verify"
#
gateway = device('gateway', 'Linux Router', 'Router', 'Lab')
address(gateway, '100.88.88.1/24')
switch1 = device('switch1', 'Catalyst 9300', 'Switch', 'Lab')
address(switch1, '100.88.88.5/24')
switch2 = device('switch2', 'Catalyst 2960', 'Switch', 'Lab', status='staged')  # first keys auto-accepted
address(switch2, '100.88.88.6/24')

# The sshd container of the dev setup; planned, so its first keys are accepted without approval
# The SSH containers of the dev setup, one per OpenSSH generation. Planned, so their first keys are
# accepted without approval.
for name, ip in (('lab-ssh-10', '192.168.250.10'), ('lab-ssh-9', '192.168.250.11'),
                 ('lab-ssh-8', '192.168.250.12'), ('lab-ssh-7', '192.168.250.13')):
    host = device(name, 'Linux Router', 'Server', 'Lab', status='planned', tenant=tenant_srv)
    address(host, f'{ip}/24', f'{name}.dev.example.net')


#
# Key material
#

def _pub(private):
    data = private.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return data.decode().split()[1]


def _ssh_string(b):
    return struct.pack('>I', len(b)) + b


def _mpint(n):
    return _ssh_string(n.to_bytes((n.bit_length() + 8) // 8, 'big'))


_RSA_CACHE = {}


def new_key(kind):
    if kind == 'ed25519':
        return _pub(ed25519.Ed25519PrivateKey.generate())
    if kind.startswith('ecdsa'):
        curve = {'ecdsa256': ec.SECP256R1, 'ecdsa384': ec.SECP384R1, 'ecdsa521': ec.SECP521R1}[kind]()
        return _pub(ec.generate_private_key(curve))
    if kind.startswith('rsa'):
        return _pub(rsa.generate_private_key(65537, int(kind[3:])))
    if kind == 'dsa':
        numbers = dsa.generate_private_key(1024).private_numbers().public_numbers
        p = numbers.parameter_numbers
        blob = (_ssh_string(b'ssh-dss') + _mpint(p.p) + _mpint(p.q) + _mpint(p.g) + _mpint(numbers.y))
        return base64.b64encode(blob).decode()
    raise ValueError(kind)


#
# Scan profiles: what a server of that kind offers
#
OPENSSH_10 = {
    'banner': 'SSH-2.0-OpenSSH_10.0p2 Debian-7',
    'kex': ['mlkem768x25519-sha256', 'sntrup761x25519-sha512', 'curve25519-sha256', 'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'],
    'hostkey': ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'],
    'ciphers': ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-ctr'],
    'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'],
}
OPENSSH_89 = {
    'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
    'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256',
            'sntrup761x25519-sha512@openssh.com', 'diffie-hellman-group14-sha256'],
    'hostkey': ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'],
    'ciphers': ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes256-gcm@openssh.com'],
    'macs': ['umac-64-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha1-etm@openssh.com',
             'hmac-sha2-256', 'hmac-sha1'],
}
OPENSSH_74 = {
    'banner': 'SSH-2.0-OpenSSH_7.4',
    'kex': ['curve25519-sha256', 'ecdh-sha2-nistp256', 'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    'hostkey': ['ssh-rsa', 'rsa-sha2-512', 'ecdsa-sha2-nistp256', 'ssh-ed25519'],
    'ciphers': ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes128-cbc', '3des-cbc'],
    'macs': ['hmac-sha2-256', 'hmac-sha1', 'hmac-md5'],
}
CISCO_LEGACY = {
    'banner': 'SSH-2.0-Cisco-1.25',
    'kex': ['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    'hostkey': ['ssh-rsa'],
    'ciphers': ['aes128-cbc', '3des-cbc', 'aes192-cbc', 'aes256-cbc'],
    'macs': ['hmac-sha1', 'hmac-sha1-96', 'hmac-md5', 'hmac-md5-96'],
}
CISCO_IOSXE = {
    'banner': 'SSH-2.0-Cisco-1.25',
    'kex': ['ecdh-sha2-nistp256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1'],
    'hostkey': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],
    'ciphers': ['aes128-gcm', 'aes256-gcm', 'aes128-ctr', 'aes256-ctr'],
    'macs': ['hmac-sha2-256', 'hmac-sha2-512'],
}
JUNOS = {
    'banner': 'SSH-2.0-OpenSSH_8.6',
    'kex': ['curve25519-sha256', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha256'],
    'hostkey': ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512'],
    'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes256-gcm@openssh.com'],
    'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512'],
}
FORTI = {
    'banner': 'SSH-2.0-tMIemdDyyHC',
    'kex': ['curve25519-sha256@libssh.org', 'diffie-hellman-group14-sha256', 'diffie-hellman-group-exchange-sha256'],
    'hostkey': ['rsa-sha2-512', 'ssh-ed25519'],
    'ciphers': ['aes256-ctr', 'aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'],
    'macs': ['hmac-sha2-256', 'hmac-sha2-512'],
}
DROPBEAR_BMC = {
    'banner': 'SSH-2.0-dropbear_2019.78',
    'kex': ['curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1'],
    'hostkey': ['ssh-rsa', 'ecdsa-sha2-nistp256'],
    'ciphers': ['aes128-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc'],
    'macs': ['hmac-sha1', 'hmac-sha2-256'],
}


#
# Invented hosts: (name, kind, model or None for a VM, role, site, profile, key kinds, address mode)
#
V4 = iter(f'{net}.{i}/24' for net in ('192.0.2', '198.51.100', '203.0.113') for i in range(10, 250))
V6 = iter(f'2001:db8:{net:x}::{i:x}/64' for net in (0x10, 0x20, 0x30) for i in range(0x10, 0x200))

PLAN = []
for i in range(1, 9):
    PLAN.append((f'sw-bern-{i:02d}', 'Catalyst 9300', 'Switch', 'RZ Bern', CISCO_IOSXE, ['rsa2048'], 'dual'))
for i in range(1, 6):
    PLAN.append((f'sw-thun-{i:02d}', 'Catalyst 2960', 'Switch', 'Filiale Thun', CISCO_LEGACY,
                 ['rsa1024' if i % 2 else 'rsa2048'], 'v4'))
for i in range(1, 4):
    PLAN.append((f'sw-zh-{i:02d}', 'DCS-7050', 'Switch', 'RZ Zuerich', OPENSSH_89, ['ed25519', 'rsa3072'], 'v6'))
for i in range(1, 3):
    PLAN.append((f'rt-core-{i:02d}', 'MX204', 'Router', 'RZ Bern', JUNOS, ['ed25519', 'ecdsa256', 'rsa3072'], 'dual'))
PLAN.append(('rt-edge-zh', 'MX204', 'Router', 'RZ Zuerich', JUNOS, ['ed25519', 'ecdsa384'], 'v6'))
for i in range(1, 7):
    PLAN.append((f'srv-bern-{i:02d}', 'PowerEdge R650', 'Server', 'RZ Bern', OPENSSH_10,
                 ['ed25519', 'ecdsa256', 'rsa3072'], 'dual'))
for i in range(1, 4):
    PLAN.append((f'srv-zh-{i:02d}', 'PowerEdge R650', 'Server', 'RZ Zuerich', OPENSSH_74, ['rsa2048', 'ecdsa256'], 'v4'))
PLAN.append(('srv-legacy-01', 'PowerEdge R650', 'Server', 'RZ Zuerich', OPENSSH_74, ['dsa', 'rsa1024'], 'v4'))
PLAN.append(('cs-bern-01', 'CM8100', 'Console Server', 'RZ Bern', OPENSSH_89, ['ed25519', 'ecdsa521'], 'v4'))
for i in range(1, 9):
    PLAN.append((f'vm-app-{i:02d}', None, None, None, OPENSSH_10 if i <= 5 else OPENSSH_89,
                 ['ed25519', 'ecdsa256', 'rsa3072'], rng.choice(['dual', 'v4', 'v6'])))
for i in range(1, 4):
    PLAN.append((f'vm-clone-{i:02d}', None, None, None, OPENSSH_74, ['ed25519'], 'v4'))  # old template
PLAN.append(('vm-jump-01', None, None, None, OPENSSH_10, ['ed25519', 'rsa4096'], 'dual'))
for i in range(1, 4):
    PLAN.append((f'srv-nokey-{i:02d}', 'PowerEdge R650', 'Server', 'Filiale Thun', None, [], 'v4'))


def make_scan(host, endpoint, ip, profile, reachable=True, days_ago=0):
    field = 'device' if isinstance(host, Device) else 'virtual_machine'
    scan = EndpointScan(**{field: host}, endpoint=endpoint, address=ip.split('/')[0],
                        scanned_at=now - timedelta(days=days_ago, hours=rng.randint(0, 20)), reachable=reachable)
    if reachable:
        scan.banner = profile['banner']
        scan.kex = profile['kex'] + ['ext-info-s', 'kex-strict-s-v00@openssh.com']
        scan.host_key_algorithms = profile['hostkey']
        scan.ciphers = profile['ciphers']
        scan.macs = profile['macs']
        scan.update_assessment()
    else:
        scan.error = 'timed out'
    scan.save()


def make_key(host, kind, endpoint='host', status='active', source='scan', last_seen_days=0, shared=False,
             public_key=None, description=''):
    field = 'device' if isinstance(host, Device) else 'virtual_machine'
    key = HostKey(**{field: host}, endpoint=endpoint, public_key=public_key or new_key(kind), status=status,
                  source=source, shared=shared, description=description,
                  last_seen=None if last_seen_days is None else now - timedelta(days=last_seen_days, hours=2))
    key.save()  # direct save: seeded legacy data may break rules the UI enforces (e.g. unshared duplicates)
    key.tags.add(demo_tag)
    return key


# Recreate demo keys and scans
demo_hosts = list(Device.objects.filter(tags=demo_tag)) + list(VirtualMachine.objects.filter(tags=demo_tag))
for host in demo_hosts:
    host.ssh_host_keys.all().delete()
    host.ssh_endpoint_scans.all().delete()

clone_key = new_key('ed25519')
hosts = {}
for name, model, role, site, profile, kinds, mode in PLAN:
    host = device(name, model, role, site, tenant=tenant_srv if role == 'Server' else tenant_net) if model else vm(name)
    host.tags.add(demo_tag)
    hosts[name] = host
    domain = 'net.example.net' if model and role != 'Server' else 'srv.example.net'
    first = None
    if mode in ('v4', 'dual'):
        first = address(host, next(V4), f'{name}.{domain}' if rng.random() < 0.6 else '')
    if mode in ('v6', 'dual'):
        ip6 = address(host, next(V6), f'{name}.{domain}' if mode == 'v6' else '')
        first = first or ip6
    if profile is None:
        continue
    stale = rng.random() < 0.15
    make_scan(host, 'host', str(first.address), profile, days_ago=45 if stale else 0)
    for kind in kinds:
        public_key = clone_key if name.startswith('vm-clone') else None
        make_key(host, kind, last_seen_days=45 if stale else 0, public_key=public_key,
                 description='cloned from template' if public_key else '')

# Access points have an IP but no SSH: out of scope (device_roles), no card, not in the report
for i in range(1, 4):
    host = device(f'ap-thun-{i:02d}', 'C9120AXI', 'Access Point', 'Filiale Thun')
    host.tags.add(demo_tag)
    address(host, next(V4))

# Out-of-band: BMCs with their own SSH server and keys
for name in ('srv-bern-01', 'srv-bern-02', 'srv-zh-01', 'srv-legacy-01'):
    host = hosts[name]
    oob = address(host, next(V4), f'{name}-bmc.oob.example.net', oob=True)
    make_scan(host, 'oob', str(oob.address), DROPBEAR_BMC)
    make_key(host, 'rsa2048', endpoint='oob')

# HA firewall pair sharing one key (intended)
fw_key = new_key('ed25519')
for name in ('fw-bern-a', 'fw-bern-b'):
    host = device(name, 'FortiGate 100F', 'Firewall', 'RZ Bern')
    host.tags.add(demo_tag)
    ip = address(host, next(V4), f'{name}.net.example.net')
    address(host, next(V6))
    make_scan(host, 'host', str(ip.address), FORTI)
    make_key(host, 'ed25519', public_key=fw_key, shared=True, description='HA pair, same key on both members')

# A switch stack: one SSH host, keys on the master, members without IP
stack = get(VirtualChassis, name='stack-bern-a')
for position in (1, 2, 3):
    member = device(f'sw-stack-a{position}', 'Catalyst 9300', 'Switch', 'RZ Bern')
    member.tags.add(demo_tag)
    member.virtual_chassis, member.vc_position = stack, position
    member.save()
    if position == 1:
        stack.master = member
        stack.save()
        ip = address(member, next(V4), 'stack-bern-a.net.example.net')
        make_scan(member, 'host', str(ip.address), CISCO_IOSXE)
        make_key(member, 'rsa3072')

# VRRP between the core routers: the VIP is listed with the keys of both
vrrp = get(FHRPGroup, protocol='vrrp3', group_id=10, defaults={'name': 'gw-bern'})
vip = IPAddress.objects.filter(address='192.0.2.254/24').first() or IPAddress(address='192.0.2.254/24')
vip.assigned_object = vrrp
vip.dns_name = 'gw-bern.net.example.net'
vip.save()
for priority, name in ((200, 'rt-core-01'), (100, 'rt-core-02')):
    iface = Interface.objects.get(device=hosts[name], name='mgmt0')
    if not FHRPGroupAssignment.objects.filter(group=vrrp, interface_id=iface.pk).exists():
        FHRPGroupAssignment(group=vrrp, interface=iface, priority=priority).save()

# Mismatch: srv-bern-03 presented a new ed25519 key (re-installed? or someone else?)
make_key(hosts['srv-bern-03'], 'ed25519', status='pending', source='scan')
# Mismatch on a switch after an RMA that nobody recorded
make_key(hosts['sw-bern-04'], 'rsa3072', status='pending', source='scan')

# Revoked: the old key of a replaced router, must never be accepted again
make_key(hosts['rt-core-01'], 'rsa2048', status='revoked', source='import', last_seen_days=200,
         description='before RMA in 2026-06')

# Never verified: typed in by hand, no scan yet
for name in ('vm-app-07', 'vm-app-08'):
    host = hosts[name]
    host.ssh_endpoint_scans.all().delete()
    host.ssh_host_keys.update(source='manual', last_seen=None)

# Pending only: a new VM whose first scan found keys that wait for approval
host = vm('vm-new-01')
host.tags.add(demo_tag)
ip = address(host, next(V4), 'vm-new-01.srv.example.net')
make_scan(host, 'host', str(ip.address), OPENSSH_10)
make_key(host, 'ed25519', status='pending')

# Unreachable
for name in ('sw-thun-05', 'srv-zh-03'):
    host = hosts[name]
    host.ssh_endpoint_scans.update(reachable=False, error='timed out', banner='', pq_ready=False,
                                   weak_algorithms=[], kex=[], host_key_algorithms=[], ciphers=[], macs=[])

# SSH on a non-standard port
get(Service, name='ssh', parent_object_type=ContentType.objects.get_for_model(VirtualMachine),
    parent_object_id=hosts['vm-jump-01'].pk, defaults={'protocol': 'tcp', 'ports': [2222]})

print('seeded:', HostKey.objects.count(), 'host keys,', EndpointScan.objects.count(), 'scans,',
      Device.objects.count(), 'devices,', VirtualMachine.objects.count(), 'VMs')
