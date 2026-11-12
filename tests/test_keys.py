import base64
import hashlib
import hmac

import pytest

from nsf import keys

# Generated with ssh-keygen -t ed25519
ED25519 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYbl1nnH+40FpNo0pTvFus0YXQqjv0eRSCZBEFiwa4u'


def _rsa_blob(bits):
    def mpint(n):
        data = n.to_bytes((n.bit_length() + 8) // 8, 'big')
        return len(data).to_bytes(4, 'big') + data

    name = b'ssh-rsa'
    return len(name).to_bytes(4, 'big') + name + mpint(65537) + mpint((1 << (bits - 1)) | 1)


def test_parse_forms():
    plain = keys.parse_public_key(ED25519 + ' root@host')
    assert plain.key_type == 'ssh-ed25519' and plain.comment == 'root@host' and plain.bits == 256
    b64 = ED25519.split()[1]
    assert keys.parse_public_key(b64).blob == plain.blob
    assert keys.parse_public_key(f'host,10.0.0.1 {ED25519}').blob == plain.blob
    assert keys.parse_public_key(f'@revoked host {ED25519}').blob == plain.blob


def test_fingerprint_matches_ssh_keygen_format():
    key = keys.parse_public_key(ED25519)
    digest = base64.b64encode(hashlib.sha256(key.blob).digest()).decode().rstrip('=')
    assert key.fingerprint_sha256 == 'SHA256:' + digest


@pytest.mark.parametrize('text, message', [
    ('', 'No key'),
    ('ssh-ed25519', 'missing'),
    ('ssh-ed25519 !!!', 'base64'),
    ('ssh-rsa ' + ED25519.split()[1], 'does not match'),
    ('ssh-ed25519 ' + base64.b64encode(base64.b64decode(ED25519.split()[1]) + b'x').decode(), 'Trailing'),
])
def test_invalid(text, message):
    with pytest.raises(keys.InvalidKeyError, match=message):
        keys.parse_public_key(text)


def test_rsa_bits_and_weakness():
    weak = keys.PublicKey('ssh-rsa', _rsa_blob(1024))
    assert weak.bits == 1024 and weak.weak
    strong = keys.PublicKey('ssh-rsa', _rsa_blob(3072))
    assert strong.bits == 3072 and not strong.weak
    assert keys.is_weak('ssh-dss', 1024)
    assert not keys.is_weak('ssh-ed25519', 256)


def test_known_hosts_lines():
    lines = keys.known_hosts_lines(['sw1', 'sw1', '10.0.0.1'], 'ssh-ed25519', 'AAAA')
    assert lines == ['sw1,10.0.0.1 ssh-ed25519 AAAA']
    assert keys.known_hosts_lines(['sw1'], 'ssh-rsa', 'BBBB', revoked=True) == ['@revoked sw1 ssh-rsa BBBB']
    assert keys.known_hosts_lines([], 'ssh-rsa', 'BBBB') == []


def test_hashed_hostname_matches_openssh():
    salt = bytes(range(20))
    hashed = keys.hash_hostname('[sw1]:2222', salt)
    _, kind, salt_b64, digest_b64 = hashed.split('|')
    assert kind == '1' and base64.b64decode(salt_b64) == salt
    assert base64.b64decode(digest_b64) == hmac.new(salt, b'[sw1]:2222', hashlib.sha1).digest()
    assert len(keys.known_hosts_lines(['a', 'b'], 'ssh-ed25519', 'AAAA', hashed=True)) == 2


def test_host_pattern_and_ip():
    assert keys.host_pattern('sw1', 22) == 'sw1'
    assert keys.host_pattern('sw1', 2222) == '[sw1]:2222'
    assert keys.canonical_ip('2001:DB8:0:88:0:0:0:1/64') == '2001:db8:0:88::1'
    assert keys.canonical_ip('192.0.2.1/24') == '192.0.2.1'


def test_sshfp_records():
    key = keys.parse_public_key(ED25519)
    rec = keys.sshfp_records('sw1.example.net.', key.key_type, key.blob, (1, 2))
    assert rec[0] == f'sw1.example.net. IN SSHFP 4 1 {hashlib.sha1(key.blob).hexdigest()}'
    assert rec[1] == f'sw1.example.net. IN SSHFP 4 2 {hashlib.sha256(key.blob).hexdigest()}'
