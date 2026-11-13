# Using the host keys in clients

The goal: every SSH client checks host keys strictly against the file from NetBox, and nothing adds
keys on its own. Fetch the file regularly (cron, systemd timer, configuration management); the export
sends an `ETag`, so unchanged files cost little.

```bash
curl -sf -H "Authorization: Token $TOKEN" \
  "https://netbox.example.net/api/plugins/ssh-fingerprint/known-hosts/?role=switch" \
  -o /etc/ssh/ssh_known_hosts.netbox.new && mv /etc/ssh/ssh_known_hosts.netbox.new /etc/ssh/ssh_known_hosts.netbox
```

## OpenSSH (people, jump hosts, terminal servers)

```
# /etc/ssh/ssh_config.d/netbox.conf
Host *
    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts.netbox
    StrictHostKeyChecking yes
    UpdateHostKeys no
```

- `StrictHostKeyChecking yes` refuses hosts that are not in the file instead of asking.
- `UpdateHostKeys no` stops ssh from adding keys the server announces after login; NetBox decides.
- `@revoked` lines make ssh refuse a revoked key outright, even if another file still lists it.
- For files on notebooks use `hashed=1`, so the file is not a readable inventory.

## Ansible with the ssh connection (servers, OpenSSH based)

```yaml
# group_vars/all.yml
ansible_ssh_common_args: >-
  -o UserKnownHostsFile=/etc/ssh/ssh_known_hosts.netbox
  -o StrictHostKeyChecking=yes
```

Keep `host_key_checking = True` in `ansible.cfg` (the default). Remove any
`ANSIBLE_HOST_KEY_CHECKING=False`.

## Ansible network_cli, Netmiko, Paramiko (network devices)

Paramiko cannot parse `@revoked` lines and fails on the whole file. Fetch with `revoked=0`. Paramiko has
no revocation; with a reject policy it refuses every key that is not in the file, which covers revoked
keys too.

Paramiko also keeps only one key per host and key type. A VRRP/HSRP virtual IP is listed with the keys
of every router in the group, so Paramiko would keep just one of them and fail after a failover. Fetch
with `vips=0` and let Paramiko-based tools connect to the routers' own addresses, not the VIP.

```bash
curl … "https://netbox.example.net/api/plugins/ssh-fingerprint/known-hosts/?role=switch&revoked=0&vips=0" \
  -o ~/.ssh/known_hosts.netbox
```

Netmiko:

```python
ConnectHandler(
    device_type='cisco_ios', host='sw-bern-01', username=user, password=password,
    ssh_strict=True,                 # reject unknown keys
    system_host_keys=False,
    alt_host_keys=True,
    alt_key_file=os.path.expanduser('~/.ssh/known_hosts.netbox'),
)
```

Paramiko:

```python
client = paramiko.SSHClient()
client.load_host_keys(os.path.expanduser('~/.ssh/known_hosts.netbox'))
client.set_missing_host_key_policy(paramiko.RejectPolicy())
```

Ansible `network_cli` uses ansible-pylibssh when installed, otherwise Paramiko. Both read the
controller user's `~/.ssh/known_hosts`; put the export (with `revoked=0&vips=0`) there and keep
`host_key_checking` enabled. Check the behaviour of your libssh version with a revoked key before
relying on it.

## Stacks and virtual IPs

- A switch stack (virtual chassis) is one SSH host. Its keys are on the master device; the entry also
  carries the stack name, so `ssh stack-bern-a` works.
- A VRRP/HSRP virtual IP is listed once per router key. OpenSSH accepts whichever router answers.

## Connecting by IP or by name

ssh compares what you type with the file. Automation often connects by IP (`ansible_host`), people by
name. The default export (`include=both`) lists the NetBox name, the name with each configured domain
suffix, the DNS names of the primary IPs, and the IPv4 and IPv6 addresses.
