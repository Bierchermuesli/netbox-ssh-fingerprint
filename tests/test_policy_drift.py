"""
Checks that policy_data.py matches the installed ssh-audit. Skipped when ssh-audit is not installed;
the scheduled CI workflow runs it with the latest release.
"""
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip('ssh_audit')

from nsf import policy_data  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    'update_policy', Path(__file__).parent.parent / 'tools' / 'update_policy.py')
update_policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_policy)


def test_policy_matches_ssh_audit():
    version, pq, weak = update_policy.build()
    hint = f'ssh-audit {version} differs from {policy_data.SOURCE}: run tools/update_policy.py and review the diff'
    assert set(pq) == policy_data.PQ_KEX, hint
    for category, names in weak.items():
        assert names == policy_data.WEAK[category], f'{category}: {hint}'
