# End-to-end checks against the seeded demo, run inside the NetBox container:
#   docker compose exec netbox sh -c '/opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell < /demo/smoke.py'
# Scans the SSH containers of the dev setup. Runs in a transaction that is rolled back at the end.
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import Client

from dcim.models import Device
from netbox.context import current_request
from users.models import ObjectPermission, Token
from core.models import ObjectType
from virtualization.models import VirtualMachine

from netbox_ssh_fingerprint import actions
from netbox_ssh_fingerprint.models import EndpointScan, HostKey
from netbox_ssh_fingerprint.scan import scan_host

settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, 'testserver']
User = get_user_model()


class Rollback(Exception):
    pass


failed = False


def check(cond, msg):
    global failed
    print(('ok   ' if cond else 'FAIL ') + msg)
    if not cond:
        failed = True


def statuses(host):
    return sorted(f'{k.key_type}:{k.status}' for k in host.ssh_host_keys.filter(endpoint='host'))


try:
    with transaction.atomic():
        admin = User.objects.get(username='admin')

        # Scan: a planned host gets its keys accepted, an active host's keys wait for approval
        lab = Device.objects.get(name='lab-ssh-10')
        lab.ssh_host_keys.all().delete()
        out = scan_host(lab)[0]
        check(out.reachable and len(out.new_active) == 3, f'planned lab-ssh-10: 3 keys auto-accepted ({statuses(lab)})')
        scan = EndpointScan.objects.get(device=lab, endpoint='host')
        check(scan.pq_ready and 'OpenSSH_10' in scan.banner, f'lab-ssh-10 scan PQ ready ({scan.banner})')
        out = scan_host(lab)[0]
        check(len(out.matched) == 3 and not out.new_pending, 'rescan matches the stored keys')

        old = Device.objects.get(name='lab-ssh-7')
        old.ssh_host_keys.all().delete()
        old.status = 'active'
        old.save()
        out = scan_host(old)[0]
        check(len(out.new_pending) == 3 and not out.new_active, f'active lab-ssh-7: keys pending ({statuses(old)})')
        scan = EndpointScan.objects.get(device=old, endpoint='host')
        check(not scan.pq_ready and 'kex:diffie-hellman-group14-sha1' in scan.weak_algorithms,
              f'lab-ssh-7: no PQ, weak group14-sha1 ({len(scan.weak_algorithms)} weak)')

        # Approve one key, then a changed key on the host shows up as mismatch
        key = old.ssh_host_keys.get(key_type='ssh-ed25519')
        key, replaced = actions.approve(key, admin)
        check(key.status == 'active' and not replaced, 'approve activates the pending key')
        HostKey.objects.filter(pk=key.pk).update(public_key=HostKey.objects.filter(
            device=lab, key_type='ssh-ed25519').first().public_key, fingerprint_sha256='SHA256:stale')
        out = scan_host(old)[0]
        check(len(out.mismatched) == 1 and out.mismatched[0].key_type == 'ssh-ed25519',
              'changed host key is reported as mismatch')
        new = out.mismatched[0]
        new, replaced = actions.approve(new, admin)
        check(new.status == 'active' and len(replaced) == 1 and replaced[0].status == 'revoked',
              'approving the new key revokes the old one')

        # Replace hardware: all active keys revoked
        revoked = actions.replace_hardware(lab, admin)
        check(len(revoked) == 3 and not lab.ssh_host_keys.filter(status='active').exists(),
              'hardware replaced: active keys revoked')

        # Validation rules
        clone = HostKey.objects.filter(device=Device.objects.get(name='srv-bern-01'), key_type='ssh-ed25519').first()
        dup = HostKey(device=Device.objects.get(name='srv-zh-01'), public_key=clone.public_key, status='active')
        try:
            dup.full_clean()
            check(False, 'unshared duplicate key is rejected')
        except ValidationError as e:
            check('shared' in e.message_dict, 'unshared duplicate key is rejected')
        try:
            HostKey(virtual_machine=VirtualMachine.objects.first(), endpoint='oob', public_key=clone.public_key).full_clean()
            check(False, 'VM cannot have an OOB key')
        except ValidationError as e:
            check('endpoint' in e.message_dict, 'VM cannot have an OOB key')
        try:
            HostKey(device=lab, public_key='ssh-ed25519 AAAAnotakey').full_clean()
            check(False, 'invalid key is rejected')
        except ValidationError as e:
            check('public_key' in e.message_dict, 'invalid key is rejected')

        # Pages
        c = Client()
        c.force_login(admin)
        for url, needle in (
            ('/plugins/ssh-fingerprint/host-keys/', 'known_hosts'),
            (HostKey.objects.filter(status='active').first().get_absolute_url(), 'SSHFP'),
            ('/plugins/ssh-fingerprint/host-keys/add/', 'Public key'),
            ('/plugins/ssh-fingerprint/report/', 'Post-quantum readiness'),
            (old.get_absolute_url(), 'SSH Host Keys'),
            (VirtualMachine.objects.get(name='vm-app-01').get_absolute_url(), 'SSH Host Keys'),
        ):
            r = c.get(url)
            body = r.content.decode()
            check(r.status_code == 200 and needle in body, f'GET {url} (status {r.status_code})')
        r = c.get(old.get_absolute_url())
        check('no PQ KEX' in r.content.decode() and 'Fetch & verify' in r.content.decode(),
              'device card shows PQ badge and fetch button')
        r = c.get('/plugins/ssh-fingerprint/report/')
        body = r.content.decode()
        check('srv-bern-03' in body and 'vm-clone-01' in body and 'srv-nokey-01' in body,
              'report lists mismatch, clones and hosts without key')
        check('ap-thun-01' not in body, 'report skips access points (out of scope)')
        r = c.get(Device.objects.get(name='ap-thun-01').get_absolute_url())
        check(r.status_code == 200 and 'SSH Host Keys' not in r.content.decode(), 'no card on an access point')

        # UI fetch runs in the request and returns to the host page
        r = c.post(f'/plugins/ssh-fingerprint/fetch/device/{old.pk}/', follow=True)
        body = r.content.decode()
        check(r.redirect_chain[-1][0] == old.get_absolute_url() and 'key(s) match' in body,
              f'UI fetch: back on the device page with the result ({r.redirect_chain})')
        r = c.post(f'/plugins/ssh-fingerprint/fetch/device/{Device.objects.get(name="srv-nokey-01").pk}/', follow=True)
        check('not reachable' in r.content.decode(), 'UI fetch: unreachable host reported')

        # Exports
        r = c.get('/plugins/ssh-fingerprint/known-hosts/')
        kh = r.content.decode()
        check('lab-ssh-7,lab-ssh-7.dev.example.net,192.168.250.13 ssh-ed25519 ' in kh, 'known_hosts: names and IP')
        check('@revoked ' in kh, 'known_hosts: revoked keys marked')
        check('[vm-jump-01]:2222' in kh, 'known_hosts: non-standard port')
        check('2001:db8:' in kh, 'known_hosts: IPv6')
        check('srv-bern-01-bmc.oob.example.net' in kh, 'known_hosts: out-of-band endpoint')
        etag = r.headers.get('ETag')
        r = c.get('/plugins/ssh-fingerprint/known-hosts/', HTTP_IF_NONE_MATCH=etag)
        check(r.status_code == 304, 'known_hosts: 304 with matching ETag')
        r = c.get('/plugins/ssh-fingerprint/known-hosts/?include=ips&hashed=1&site=lab')
        lines = r.content.decode().splitlines()
        check(lines and all(line.startswith(('|1|', '@revoked |1|')) for line in lines), 'known_hosts: hashed, site filter')
        r = c.get('/plugins/ssh-fingerprint/known-hosts/?revoked=0')
        check('@revoked' not in r.content.decode() and 'lab-ssh-7' in r.content.decode(), 'known_hosts: revoked=0')
        r = c.get('/plugins/ssh-fingerprint/sshfp/')
        check('lab-ssh-7.dev.example.net. IN SSHFP 4 2 ' in r.content.decode(), 'SSHFP zone snippet')

        # API
        token = Token(user=admin, version=1)
        token.save()
        api = Client(HTTP_AUTHORIZATION=f'Token {token.token}')
        r = api.get('/api/plugins/ssh-fingerprint/host-keys/?weak=true')
        check(r.status_code == 200 and r.json()['count'] > 0, f'API list weak keys ({r.json().get("count")})')
        pending = HostKey.objects.filter(status='pending', device__name='lab-ssh-7').first()
        r = api.post(f'/api/plugins/ssh-fingerprint/host-keys/{pending.pk}/approve/')
        check(r.status_code == 200 and r.json()['status']['value'] == 'active', f'API approve ({r.status_code})')
        r = api.get('/api/plugins/ssh-fingerprint/known-hosts/?site=lab')
        check(r.status_code == 200 and 'lab-ssh-7' in r.content.decode(), 'API known_hosts')
        r = api.get(f'/api/plugins/ssh-fingerprint/scans/?object_type=dcim.device&object_id={old.pk}')
        check(r.status_code == 200 and r.json()[0]['pq_ready'] is False, 'API scans')
        r = api.post('/api/plugins/ssh-fingerprint/fetch/', {'object_type': 'dcim.device', 'object_id': old.pk},
                     content_type='application/json')
        check(r.status_code == 200 and r.json()[0]['reachable'] and r.json()[0]['matched'],
              f'API fetch returns the result ({r.status_code} {r.content[:200]})')
        r = api.post('/api/plugins/ssh-fingerprint/fetch/', {'object_type': 'dcim.device', 'object_id': old.pk,
                     'background': True}, content_type='application/json')
        check(r.status_code == 202 and r.json().get('job_id'), f'API fetch in background queues a job ({r.status_code})')
        r = api.get('/api/schema/')
        check(r.status_code == 200, 'API schema renders')

        # A user who may add keys but not approve them: new keys must stay pending
        clerk = User.objects.create_user('clerk', password='x')
        perm = ObjectPermission.objects.create(name='hostkeys add', actions=['view', 'add', 'change'])
        perm.object_types.set([ObjectType.objects.get_for_model(HostKey)])
        perm.users.add(clerk)
        ctoken = Token(user=clerk, version=1)
        ctoken.save()
        capi = Client(HTTP_AUTHORIZATION=f'Token {ctoken.token}')
        body = {'device': {'id': Device.objects.get(name='srv-nokey-01').pk},
                'public_key': HostKey.objects.filter(device=lab).first().public_key}
        r = capi.post('/api/plugins/ssh-fingerprint/host-keys/', {**body, 'status': 'active', 'endpoint': 'host'},
                      content_type='application/json')
        check(r.status_code == 400 and 'approve' in r.content.decode(), f'clerk cannot activate ({r.status_code} {r.content[:300]})')
        r = capi.post(f'/api/plugins/ssh-fingerprint/host-keys/{pending.pk}/revoke/')
        check(r.status_code == 200, f'clerk can revoke ({r.status_code})')
        r = capi.post('/api/plugins/ssh-fingerprint/fetch/', {'object_type': 'dcim.device', 'object_id': old.pk},
                      content_type='application/json')
        check(r.status_code == 403, f'clerk cannot fetch ({r.status_code})')

        raise Rollback
except Rollback:
    pass
finally:
    current_request.set(None)

print('SMOKE FAILED' if failed else 'SMOKE OK')
