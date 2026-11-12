import importlib.util
import sys
import types
from pathlib import Path

# Load the pure-Python modules without importing the plugin package (which needs NetBox)
_PKG = Path(__file__).parent.parent / 'netbox_ssh_fingerprint'
_pkg = types.ModuleType('nsf')
_pkg.__path__ = [str(_PKG)]
sys.modules['nsf'] = _pkg
for _name in ('keys', 'policy', 'probe'):
    _spec = importlib.util.spec_from_file_location(f'nsf.{_name}', _PKG / f'{_name}.py')
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules[f'nsf.{_name}'] = _mod
    _spec.loader.exec_module(_mod)
