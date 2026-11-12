from netbox.plugins import PluginConfig

__version__ = '0.1.0'


class SSHFingerprintConfig(PluginConfig):
    name = 'netbox_ssh_fingerprint'
    verbose_name = 'SSH Fingerprint'
    description = 'SSH host keys per device and VM, exported as known_hosts and SSHFP records'
    version = __version__
    author = 'Stefan Grosser'
    base_url = 'ssh-fingerprint'
    min_version = '4.6.5'
    default_settings = {
        # Role slugs of devices and VMs that run SSH (card, report, scans). Empty means all.
        # Hosts that already have keys always show their card.
        'device_roles': [],
        'vm_roles': [],
        # Extra name variants in known_hosts: "sw-01" plus "sw-01.<suffix>" for each suffix
        'domain_suffixes': [],
        # What known_hosts lists per host by default: names, ips or both
        'known_hosts_include': 'both',
        # A NetBox service with this name on the host sets a non-standard SSH port
        'ssh_service_name': 'ssh',
        # Keys not seen by a scan for this many days count as stale
        'stale_days': 30,
        # Seconds per connection attempt when fetching keys
        'fetch_timeout': 5,
        # SSHFP fingerprint types to export: 1 = SHA-1, 2 = SHA-256
        'sshfp_fingerprint_types': [2],
        # Host statuses for which the first key of each type is accepted without approval
        'auto_accept_statuses': ['planned', 'staged'],
    }


config = SSHFingerprintConfig
