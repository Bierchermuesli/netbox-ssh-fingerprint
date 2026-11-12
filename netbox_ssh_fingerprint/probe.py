"""
A minimal SSH client that runs the key exchange just far enough to read the server's host key, and records
the algorithms the server offers (its KEXINIT). It never authenticates and never derives session keys.

Unlike a current ssh-keyscan it also talks to legacy servers that only offer ssh-rsa, ssh-dss,
diffie-hellman-group1-sha1 or group-exchange-sha1, which is common on older network devices.
"""
import os
import secrets
import socket
import struct
from dataclasses import dataclass, field

from .keys import InvalidKeyError, PublicKey, parse_blob

CLIENT_BANNER = b'SSH-2.0-netbox_ssh_fingerprint_probe\r\n'

MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_KEXINIT = 20
MSG_KEX_INIT = 30          # KEXDH_INIT and KEX_ECDH_INIT
MSG_KEX_REPLY = 31         # KEXDH_REPLY, KEX_ECDH_REPLY and KEX_DH_GEX_GROUP
MSG_GEX_INIT = 32
MSG_GEX_REPLY = 33
MSG_GEX_REQUEST = 34


def _pi_scaled(bits):
    """
    floor(pi * 2**bits), with Machin's formula in integer arithmetic.
    """
    guard = 64
    one = 1 << (bits + guard)

    def arctan_inv(x):
        total = term = one // x
        x2, n, sign = x * x, 1, 1
        while term:
            term //= x2
            n += 2
            sign = -sign
            total += sign * (term // n)
        return total

    return (4 * (4 * arctan_inv(5) - arctan_inv(239))) >> guard


def _modp_prime(bits, k):
    """
    The MODP primes of RFC 2409 and RFC 3526: 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + k).
    """
    return (1 << bits) - (1 << (bits - 64)) - 1 + (1 << 64) * (_pi_scaled(bits - 130) + k)


_PRIMES = {}


def _prime(bits):
    if bits not in _PRIMES:
        k = {1024: 129093, 2048: 124476, 4096: 240904, 8192: 4743158}[bits]
        _PRIMES[bits] = _modp_prime(bits, k)
    return _PRIMES[bits]


DH_GROUPS = {
    'diffie-hellman-group14-sha256': 2048,
    'diffie-hellman-group16-sha512': 4096,
    'diffie-hellman-group18-sha512': 8192,
    'diffie-hellman-group14-sha1': 2048,
    'diffie-hellman-group1-sha1': 1024,
}
GEX = ('diffie-hellman-group-exchange-sha256', 'diffie-hellman-group-exchange-sha1')
X25519 = ('curve25519-sha256', 'curve25519-sha256@libssh.org')
ECDH = ('ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521')

# What the probe offers, preferred first. Post-quantum hybrids are not implemented here; whether the
# server offers them is read from its KEXINIT.
CLIENT_KEX = (
    *X25519, *ECDH,
    'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1',
)

# Host key algorithms grouped by the key they return
HOST_KEY_FAMILIES = {
    'ssh-ed25519': ('ssh-ed25519',),
    'ssh-ed448': ('ssh-ed448',),
    'ecdsa': ('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'),
    'ssh-rsa': ('rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'),
    'ssh-dss': ('ssh-dss',),
}
ALL_HOST_KEY_ALGORITHMS = tuple(a for algs in HOST_KEY_FAMILIES.values() for a in algs)

# Offered only so negotiation succeeds; the probe stops before any of these is used
CLIENT_CIPHERS = (
    'chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
    'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes256-cbc', '3des-cbc',
)
CLIENT_MACS = (
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512',
    'hmac-sha1', 'hmac-md5',
)


class ProbeError(Exception):
    pass


@dataclass
class ServerOffer:
    kex: list = field(default_factory=list)
    host_key_algorithms: list = field(default_factory=list)
    ciphers: list = field(default_factory=list)
    macs: list = field(default_factory=list)
    compression: list = field(default_factory=list)


@dataclass
class ProbeResult:
    address: str
    port: int
    banner: str = ''
    offer: ServerOffer = field(default_factory=ServerOffer)
    keys: list = field(default_factory=list)          # PublicKey
    errors: list = field(default_factory=list)

    @property
    def reachable(self):
        return bool(self.banner)


def _string(value):
    if isinstance(value, str):
        value = value.encode()
    return struct.pack('>I', len(value)) + value


def _namelist(names):
    return _string(','.join(names))


def _mpint(value):
    data = value.to_bytes((value.bit_length() + 8) // 8, 'big') if value else b''
    return _string(data)


class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ProbeError('Truncated packet')
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def byte(self):
        return self.take(1)[0]

    def uint32(self):
        return struct.unpack('>I', self.take(4))[0]

    def string(self):
        return self.take(self.uint32())

    def namelist(self):
        value = self.string().decode('ascii', 'replace')
        return [n for n in value.split(',') if n]

    def mpint(self):
        return int.from_bytes(self.string(), 'big', signed=True)


class _Connection:
    def __init__(self, address, port, timeout):
        self.sock = socket.create_connection((address, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.file = self.sock.makefile('rb')

    def close(self):
        try:
            self.file.close()
            self.sock.close()
        except OSError:
            pass

    def banner(self):
        self.sock.sendall(CLIENT_BANNER)
        for _ in range(50):  # servers may send other lines before the version line
            line = self.file.readline(256)
            if not line:
                raise ProbeError('Connection closed before the SSH banner')
            if line.startswith(b'SSH-'):
                return line.decode('ascii', 'replace').strip()
        raise ProbeError('No SSH banner')

    def send(self, payload):
        padding = 8 - (len(payload) + 5) % 8
        if padding < 4:
            padding += 8
        packet = struct.pack('>IB', len(payload) + padding + 1, padding) + payload + os.urandom(padding)
        self.sock.sendall(packet)

    def recv(self):
        while True:
            header = self.file.read(4)
            if len(header) < 4:
                raise ProbeError('Connection closed by the server')
            length = struct.unpack('>I', header)[0]
            if length > 256 * 1024:
                raise ProbeError('Packet too large')
            data = self.file.read(length)
            if len(data) < length:
                raise ProbeError('Connection closed by the server')
            payload = data[1:length - data[0]]
            if not payload:
                continue
            msg = payload[0]
            if msg in (MSG_IGNORE, MSG_DEBUG, MSG_UNIMPLEMENTED):
                continue
            if msg == MSG_DISCONNECT:
                reader = _Reader(payload[1:])
                reader.uint32()
                raise ProbeError('Server disconnected: ' + reader.string().decode('utf-8', 'replace'))
            return msg, _Reader(payload[1:])


def _kexinit(host_key_algorithms):
    return (
        bytes([MSG_KEXINIT]) + os.urandom(16)
        + _namelist(CLIENT_KEX) + _namelist(host_key_algorithms)
        + _namelist(CLIENT_CIPHERS) * 2 + _namelist(CLIENT_MACS) * 2
        + _namelist(['none']) * 2 + _namelist([]) * 2
        + b'\x00' + struct.pack('>I', 0)
    )


def parse_kexinit(reader):
    reader.take(16)  # cookie
    lists = [reader.namelist() for _ in range(10)]
    return ServerOffer(
        kex=lists[0], host_key_algorithms=lists[1], ciphers=lists[2], macs=lists[4], compression=lists[6],
    )


def _ephemeral(kex):
    """
    Our public value for the key exchange. The secret is thrown away; we only need the server's reply.
    """
    if kex in X25519:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        return _string(X25519PrivateKey.generate().public_key().public_bytes_raw())
    if kex in ECDH:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        curve = {'ecdh-sha2-nistp256': ec.SECP256R1, 'ecdh-sha2-nistp384': ec.SECP384R1,
                 'ecdh-sha2-nistp521': ec.SECP521R1}[kex]()
        point = ec.generate_private_key(curve).public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        return _string(point)
    p = _prime(DH_GROUPS[kex])
    return _mpint(pow(2, secrets.randbits(256) | 1, p))


def _negotiate(client, server, what):
    for name in client:
        if name in server:
            return name
    raise ProbeError(f'No common {what} algorithm (server offers: {", ".join(server) or "none"})')


def fetch_one(address, port, timeout, host_key_algorithms):
    """
    One connection: banner, KEXINIT and key exchange until the server's reply carries its host key.
    Returns (banner, server offer, host key blob).
    """
    conn = _Connection(address, port, timeout)
    try:
        banner = conn.banner()
        conn.send(_kexinit(host_key_algorithms))
        msg, reader = conn.recv()
        if msg != MSG_KEXINIT:
            raise ProbeError(f'Expected KEXINIT, got message {msg}')
        offer = parse_kexinit(reader)
        kex = _negotiate(CLIENT_KEX, offer.kex, 'key exchange')
        _negotiate(host_key_algorithms, offer.host_key_algorithms, 'host key')

        if kex in GEX:
            conn.send(bytes([MSG_GEX_REQUEST]) + struct.pack('>III', 1024, 2048, 8192))
            msg, reader = conn.recv()
            if msg != MSG_KEX_REPLY:
                raise ProbeError(f'Expected DH group, got message {msg}')
            p, g = reader.mpint(), reader.mpint()
            conn.send(bytes([MSG_GEX_INIT]) + _mpint(pow(g, secrets.randbits(256) | 1, p)))
            expected = MSG_GEX_REPLY
        else:
            conn.send(bytes([MSG_KEX_INIT]) + _ephemeral(kex))
            expected = MSG_KEX_REPLY
        msg, reader = conn.recv()
        if msg != expected:
            raise ProbeError(f'Expected key exchange reply, got message {msg}')
        return banner, offer, reader.string()
    finally:
        conn.close()


def probe(address, port=22, timeout=5):
    """
    Read every host key the server has (one connection per key family) and its algorithm offer.
    Errors are collected in the result; an unreachable host has no banner.
    """
    result = ProbeResult(address=str(address), port=int(port))
    try:
        banner, offer, blob = fetch_one(address, port, timeout, ALL_HOST_KEY_ALGORITHMS)
    except (OSError, ProbeError) as e:
        result.errors.append(str(e) or e.__class__.__name__)
        return result
    result.banner, result.offer = banner, offer
    blobs = [blob]

    first_type = _key_type(blob)
    for family, algorithms in HOST_KEY_FAMILIES.items():
        offered = [a for a in algorithms if a in offer.host_key_algorithms]
        if not offered or (first_type and _family(first_type) == family):
            continue
        try:
            blobs.append(fetch_one(address, port, timeout, offered)[2])
        except (OSError, ProbeError) as e:
            result.errors.append(f'{family}: {e}')

    for blob in blobs:
        try:
            result.keys.append(PublicKey(key_type=parse_blob(blob), blob=blob))
        except InvalidKeyError as e:
            result.errors.append(f'Unusable host key: {e}')
    return result


def _key_type(blob):
    try:
        return parse_blob(blob)
    except InvalidKeyError:
        return None


def _family(key_type):
    return 'ecdsa' if key_type.startswith('ecdsa-') else key_type
