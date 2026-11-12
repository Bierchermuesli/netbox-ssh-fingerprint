"""
SSH public key parsing, fingerprints and known_hosts/SSHFP formatting.

Pure Python without Django, so it can be tested and reused without NetBox.
"""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import struct
from dataclasses import dataclass

# Key type -> SSHFP algorithm number (RFC 4255, 6594, 7479, 8709)
SSHFP_ALGORITHMS = {
    'ssh-rsa': 1,
    'ssh-dss': 2,
    'ecdsa-sha2-nistp256': 3,
    'ecdsa-sha2-nistp384': 3,
    'ecdsa-sha2-nistp521': 3,
    'ssh-ed25519': 4,
    'ssh-ed448': 6,
}
KEY_TYPES = tuple(SSHFP_ALGORITHMS)

# SSHFP fingerprint types
SSHFP_SHA1 = 1
SSHFP_SHA256 = 2

ECDSA_BITS = {'nistp256': 256, 'nistp384': 384, 'nistp521': 521}
MIN_RSA_BITS = 2048


class InvalidKeyError(ValueError):
    pass


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    blob: bytes
    comment: str = ''

    @property
    def b64(self):
        return base64.b64encode(self.blob).decode()

    @property
    def fingerprint_sha256(self):
        return fingerprint_sha256(self.blob)

    @property
    def bits(self):
        return key_bits(self.key_type, self.blob)

    @property
    def weak(self):
        return is_weak(self.key_type, self.bits)


def _read_string(blob, offset):
    if offset + 4 > len(blob):
        raise InvalidKeyError('Truncated key data')
    (length,) = struct.unpack('>I', blob[offset:offset + 4])
    start = offset + 4
    end = start + length
    if end > len(blob):
        raise InvalidKeyError('Truncated key data')
    return blob[start:end], end


def _mpint_bits(value):
    return int.from_bytes(value, 'big').bit_length()


def parse_blob(blob):
    """
    Validate a key blob and return its key type.
    """
    key_type, offset = _read_string(blob, 0)
    try:
        key_type = key_type.decode('ascii')
    except UnicodeDecodeError:
        raise InvalidKeyError('Invalid key type')
    if key_type not in SSHFP_ALGORITHMS:
        raise InvalidKeyError(f'Unsupported key type "{key_type}"')
    # Walk the remaining fields so truncated or padded blobs are rejected
    fields = {'ssh-rsa': 2, 'ssh-dss': 4, 'ssh-ed25519': 1, 'ssh-ed448': 1}.get(key_type, 2)
    for _ in range(fields):
        _, offset = _read_string(blob, offset)
    if offset != len(blob):
        raise InvalidKeyError('Trailing data after key')
    return key_type


def parse_public_key(text):
    """
    Parse a public key from one of these forms:

    - "ssh-ed25519 AAAA... comment" (a .pub file)
    - "AAAA..." (the base64 part alone)
    - "host ssh-ed25519 AAAA..." (a known_hosts or ssh-keyscan line, the host is ignored)
    """
    parts = (text or '').strip().split()
    if not parts:
        raise InvalidKeyError('No key given')
    if parts[0].startswith('@'):
        parts = parts[1:]
    if len(parts) >= 3 and parts[0] not in SSHFP_ALGORITHMS and parts[1] in SSHFP_ALGORITHMS:
        parts = parts[1:]

    if parts[0] in SSHFP_ALGORITHMS:
        if len(parts) < 2:
            raise InvalidKeyError('Key data missing after the key type')
        declared, data, comment = parts[0], parts[1], ' '.join(parts[2:])
    else:
        declared, data, comment = None, parts[0], ' '.join(parts[1:])

    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidKeyError('Key data is not valid base64')
    key_type = parse_blob(blob)
    if declared and declared != key_type:
        raise InvalidKeyError(f'Key type "{declared}" does not match the key data ({key_type})')
    return PublicKey(key_type=key_type, blob=blob, comment=comment)


def fingerprint_sha256(blob):
    digest = hashlib.sha256(blob).digest()
    return 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')


def sshfp_digest(blob, fp_type=SSHFP_SHA256):
    if fp_type == SSHFP_SHA1:
        return hashlib.sha1(blob).hexdigest()
    if fp_type == SSHFP_SHA256:
        return hashlib.sha256(blob).hexdigest()
    raise ValueError(f'Unsupported SSHFP fingerprint type {fp_type}')


def key_bits(key_type, blob):
    _, offset = _read_string(blob, 0)
    if key_type == 'ssh-rsa':
        _, offset = _read_string(blob, offset)  # e
        n, _ = _read_string(blob, offset)
        return _mpint_bits(n)
    if key_type == 'ssh-dss':
        p, _ = _read_string(blob, offset)
        return _mpint_bits(p)
    if key_type.startswith('ecdsa-sha2-'):
        return ECDSA_BITS.get(key_type.rsplit('-', 1)[1], 0)
    if key_type == 'ssh-ed25519':
        return 256
    if key_type == 'ssh-ed448':
        return 456
    return 0


def is_weak(key_type, bits):
    if key_type == 'ssh-dss':
        return True
    if key_type == 'ssh-rsa':
        return bits < MIN_RSA_BITS
    return False


def canonical_ip(address):
    """
    The form ssh writes and compares: IPv6 compressed and lowercase, no prefix length.
    """
    return ipaddress.ip_address(str(address).split('/')[0]).compressed


def host_pattern(name, port=22):
    return name if not port or int(port) == 22 else f'[{name}]:{port}'


def hash_hostname(pattern, salt=None):
    """
    Hash a host pattern the way ssh-keygen -H does: |1|base64(salt)|base64(HMAC-SHA1(salt, host)).
    """
    salt = salt if salt is not None else os.urandom(20)
    digest = hmac.new(salt, pattern.encode(), hashlib.sha1).digest()
    return f'|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}'


def known_hosts_lines(patterns, key_type, b64, revoked=False, hashed=False):
    """
    One line per key with all host patterns comma separated, or one line per pattern when hashed.
    """
    patterns = list(dict.fromkeys(p for p in patterns if p))
    if not patterns:
        return []
    marker = '@revoked ' if revoked else ''
    if hashed:
        return [f'{marker}{hash_hostname(p)} {key_type} {b64}' for p in patterns]
    return [f'{marker}{",".join(patterns)} {key_type} {b64}']


def sshfp_records(owner, key_type, blob, fp_types=(SSHFP_SHA256,), ttl=None):
    ttl = f' {ttl}' if ttl else ''
    return [
        f'{owner}{ttl} IN SSHFP {SSHFP_ALGORITHMS[key_type]} {t} {sshfp_digest(blob, t)}'
        for t in fp_types
    ]
