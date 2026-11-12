"""
Rates the algorithms an SSH server offers. Adapted from the ssh-audit hardening policies, the OpenSSH
defaults and release notes, and BSI TR-02102-4.

Post-quantum readiness is about the key exchange: a recorded session can only be decrypted later
("store now, decrypt later") if the key exchange is broken. OpenSSH has no post-quantum host key
signatures yet, so host keys are rated classically.
"""
from dataclasses import dataclass, field

PQ_KEX = {
    'mlkem768x25519-sha256',
    'mlkem768nistp256-sha256',
    'mlkem1024nistp384-sha384',
    'sntrup761x25519-sha512',
    'sntrup761x25519-sha512@openssh.com',
}

# Broken or too weak: SHA-1 or 1024-bit groups
WEAK_KEX = {
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
    'rsa1024-sha1',
    'gss-group1-sha1-',
    'gss-gex-sha1-',
    'gss-group14-sha1-',
}

# ssh-rsa signs with SHA-1 (disabled by default since OpenSSH 8.8); DSA is gone since OpenSSH 10.0
WEAK_HOST_KEY_ALGORITHMS = {
    'ssh-dss',
    'ssh-rsa',
    'ssh-dss-cert-v01@openssh.com',
    'ssh-rsa-cert-v01@openssh.com',
}

WEAK_CIPHERS = {
    'none',
    '3des-cbc',
    'blowfish-cbc',
    'cast128-cbc',
    'arcfour',
    'arcfour128',
    'arcfour256',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'rijndael-cbc@lysator.liu.se',
}

WEAK_MACS = {
    'none',
    'hmac-md5',
    'hmac-md5-96',
    'hmac-md5-etm@openssh.com',
    'hmac-md5-96-etm@openssh.com',
    'hmac-sha1',
    'hmac-sha1-96',
    'hmac-sha1-etm@openssh.com',
    'hmac-sha1-96-etm@openssh.com',
    'hmac-ripemd160',
    'hmac-ripemd160@openssh.com',
    'umac-64@openssh.com',
    'umac-64-etm@openssh.com',
}

# Pseudo algorithms that only signal extensions
_MARKERS = ('ext-info-', 'kex-strict-')


@dataclass
class Assessment:
    pq_ready: bool = False
    weak: dict = field(default_factory=dict)   # category -> [algorithms]

    @property
    def weak_count(self):
        return sum(len(v) for v in self.weak.values())

    @property
    def weak_list(self):
        return [f'{category}:{alg}' for category, algs in self.weak.items() for alg in algs]


def _weak(offered, weak):
    return [a for a in offered if a in weak or any(a.startswith(w) for w in weak if w.endswith('-'))]


def assess(kex=(), host_key_algorithms=(), ciphers=(), macs=()):
    kex = [k for k in kex if not k.startswith(_MARKERS)]
    weak = {
        'kex': _weak(kex, WEAK_KEX),
        'hostkey': _weak(host_key_algorithms, WEAK_HOST_KEY_ALGORITHMS),
        'cipher': _weak(ciphers, WEAK_CIPHERS),
        'mac': _weak(macs, WEAK_MACS),
    }
    return Assessment(
        pq_ready=any(k in PQ_KEX for k in kex),
        weak={k: v for k, v in weak.items() if v},
    )
