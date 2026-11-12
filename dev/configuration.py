PLUGINS = ["netbox_ssh_fingerprint"]
PLUGINS_CONFIG = {
    "netbox_ssh_fingerprint": {
        # Access points, patch panels and the like never run SSH
        "device_roles": ["router", "switch", "firewall", "server", "console-server"],
        "domain_suffixes": [],
    },
}
