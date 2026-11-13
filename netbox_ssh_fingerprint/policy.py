"""
Rates the algorithms an SSH server offers.

The lists in policy_data.py are generated from the algorithm database of ssh-audit
(tools/update_policy.py) and checked against its latest release by a scheduled CI job. See the README
for the sources and the deliberate deviations.

Post-quantum readiness is about the key exchange: a recorded session can only be decrypted later
("store now, decrypt later") if the key exchange is broken. OpenSSH has no post-quantum host key
signatures yet, so host keys are rated classically.
"""
from dataclasses import dataclass, field

from .policy_data import PQ_KEX, SOURCE, WEAK

# Pseudo algorithms that only signal extensions
_MARKERS = ('ext-info-', 'kex-strict-')

__all__ = ('PQ_KEX', 'SOURCE', 'WEAK', 'Assessment', 'assess', 'weak_reason')


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


def weak_reason(category, algorithm):
    """
    Why the algorithm is weak, or None. Entries ending in * (e.g. gss-group1-sha1-*) match by prefix.
    """
    names = WEAK.get(category, {})
    if algorithm in names:
        return names[algorithm]
    for name, reason in names.items():
        if name.endswith('*') and algorithm.startswith(name[:-1]):
            return reason
    return None


def assess(kex=(), host_key_algorithms=(), ciphers=(), macs=()):
    kex = [k for k in kex if not k.startswith(_MARKERS)]
    offered = {'kex': kex, 'hostkey': host_key_algorithms, 'cipher': ciphers, 'mac': macs}
    weak = {
        category: [a for a in algorithms if weak_reason(category, a)]
        for category, algorithms in offered.items()
    }
    return Assessment(
        pq_ready=any(k in PQ_KEX for k in kex),
        weak={k: v for k, v in weak.items() if v},
    )
