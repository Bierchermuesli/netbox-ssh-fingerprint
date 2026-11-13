# netbox-ssh-fingerprint

NetBox plugin that keeps the SSH host keys of devices and virtual machines in NetBox, the source of
truth, and hands them out as `known_hosts` files and SSHFP records. It fetches and verifies keys from
the hosts, reports hosts without keys, changed keys, weak keys and duplicates, and shows which hosts
offer a post-quantum key exchange.

Status: **MVP**. Requires NetBox 4.6.5 or newer.

## Why

Without a reference for host keys, the first connection to a host is a blind "yes" (trust on first
use), and automation usually runs with host key checking switched off (`StrictHostKeyChecking=no`,
`host_key_checking = False`, Paramiko's `AutoAddPolicy`). Nobody then knows whether the device on the
other end is the one they think it is:

- an IP address was reused, a DNS entry is stale, a device was swapped (RMA) or re-installed;
- automation pushes configuration to the wrong device;
- network devices often use password authentication, so connecting to the wrong host hands it an
  admin password;
- people learn to clear host key warnings with `ssh-keygen -R`, and then the check is worthless when it
  matters.

A hostname proves nothing; the host key is the only thing cryptographically bound to the device.

## What it does

- **Host keys per device and VM**, for the host itself and for its out-of-band interface (BMC,
  console), which runs its own SSH server. Stores the full public key; SHA-256 fingerprint, key size
  and SSHFP digests are derived from it.
- **Lifecycle**: `pending`, `active`, `revoked`. Activating a key needs the `approve` permission. A host
  in status `planned` or `staged` gets its first key of each type accepted automatically, so
  provisioning needs no manual step. Approving a new key revokes the previous one of that type.
- **Fetch & verify** button on device and VM pages (`fetch` permission). A background job connects to
  the host, reads its keys and compares them. New keys wait for approval; a key that differs from the
  active one is a mismatch. Changes land in the NetBox changelog under the user who started the job.
- **Legacy devices**: the fetcher speaks just enough SSH to read the host key. It also works with
  servers a current `ssh-keyscan` can no longer talk to, such as older Cisco IOS offering only
  `ssh-rsa`, `diffie-hellman-group14-sha1` or `group1-sha1`.
- **Algorithm scan**: banner, key exchange, host key algorithms, ciphers and MACs of every endpoint,
  rated after the ssh-audit hardening policies, the OpenSSH defaults and BSI TR-02102-4.
- **Post-quantum readiness**: whether a host offers `mlkem768x25519-sha256` or
  `sntrup761x25519-sha512`. Without it, recorded sessions can be decrypted once large quantum
  computers exist (store now, decrypt later). OpenSSH has no post-quantum host key signatures yet, so
  this is about the key exchange only.
- **Hardware replaced / re-installed**: revokes the active keys of a host and fetches the new ones.
- **`known_hosts` export** filtered by site, tenant, role or tag: host names, IPv4 and IPv6 addresses
  or both, `[host]:port` for a NetBox service named `ssh` on another port, optional hashed host names,
  `@revoked` lines for revoked keys so ssh refuses them. `ETag` support for cheap polling.
- **SSHFP export** as a zone file snippet.
- **Report**: hosts without key, stale keys, mismatches, weak keys (DSA, RSA below 2048 bits),
  duplicates (intended for HA pairs when marked as shared, otherwise usually a cloned VM image),
  post-quantum readiness, weak algorithms, SSH software in use, unreachable hosts.
- **REST API** for everything, including approve, revoke, fetch and the exports.

## Installation

```bash
pip install git+https://github.com/Bierchermuesli/netbox-ssh-fingerprint.git
```

```python
# configuration.py
PLUGINS = ['netbox_ssh_fingerprint']
PLUGINS_CONFIG = {
    'netbox_ssh_fingerprint': {
        'device_roles': ['router', 'switch', 'firewall', 'server'],
    },
}
```

```bash
python manage.py migrate netbox_ssh_fingerprint
```

The fetch job runs on the NetBox worker (`manage.py rqworker`), which needs to reach the SSH ports of
the hosts.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `device_roles` | `[]` | Device role slugs that run SSH: card, report and scans. Empty means all. Hosts with keys always show their card. |
| `vm_roles` | `[]` | The same for virtual machines. |
| `domain_suffixes` | `[]` | Extra name variants in `known_hosts`: `sw-01` plus `sw-01.<suffix>`. DNS names of the primary IPs are always included. |
| `known_hosts_include` | `both` | Default for `include`: `names`, `ips` or `both`. |
| `ssh_service_name` | `ssh` | A NetBox service with this name sets a non-standard SSH port. |
| `stale_days` | `30` | Active keys not seen by a scan for longer count as stale. |
| `fetch_timeout` | `5` | Seconds per connection attempt. |
| `sshfp_fingerprint_types` | `[2]` | SSHFP fingerprint types: `1` SHA-1, `2` SHA-256. |
| `auto_accept_statuses` | `['planned', 'staged']` | Host statuses whose first key of each type is accepted without approval. |

## Permissions

Standard NetBox object permissions on *Host key* (`view`, `add`, `change`, `delete`, with constraints
such as a site), plus two actions:

- `approve`: activate a key. Without it, new keys can only be saved as `pending`.
- `fetch`: start the fetch & verify job.

Give scanners and automation their own user and token, and people their own permissions.

## Exports

| UI | API |
|---|---|
| `/plugins/ssh-fingerprint/known-hosts/` | `/api/plugins/ssh-fingerprint/known-hosts/` |
| `/plugins/ssh-fingerprint/sshfp/` | `/api/plugins/ssh-fingerprint/sshfp/` |

Both take the host key filters (`site`, `tenant`, `role`, `host_tag`, `device_id`, …). `known-hosts`
also takes `include=both|names|ips`, `hashed=1`, and `revoked=0` to leave out the `@revoked` lines.

```bash
curl -s -H "Authorization: Token $TOKEN" \
  "https://netbox.example.net/api/plugins/ssh-fingerprint/known-hosts/?role=switch&site=bern" \
  > /etc/ssh/ssh_known_hosts.d/netbox
```

How to use the file with OpenSSH, Ansible, Netmiko and Paramiko: [docs/clients.md](docs/clients.md).

## API

- `/api/plugins/ssh-fingerprint/host-keys/`: CRUD; `POST …/{id}/approve/`, `POST …/{id}/revoke/`
- `POST /api/plugins/ssh-fingerprint/fetch/` with `{"object_type": "dcim.device", "object_id": 1}`
- `GET /api/plugins/ssh-fingerprint/scans/?object_type=dcim.device&object_id=1`

## SSHFP and DNSSEC

OpenSSH trusts SSHFP records automatically (`VerifyHostKeyDNS yes`) only when the answer is DNSSEC
validated: the resolver sets the AD bit and the client trusts it (`options trust-ad` in
`resolv.conf`). Without DNSSEC, ssh shows "Matching host key fingerprint found in DNS" but still asks.
Internal zones can be signed internally with the trust anchor configured on the internal resolvers;
no public DNSSEC chain is needed. Until then, `known_hosts` does the work.

## Development

```bash
cd dev
docker compose up -d     # http://localhost:8014, admin / admin
docker compose exec netbox sh -c '/opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell < /demo/smoke.py'
uvx pytest tests          # unit tests, no NetBox needed
```

The demo seeds about 60 hosts in the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, `2001:db8::/32`) with every report case, and four SSH containers of different
OpenSSH generations to fetch from: `lab-ssh-10` (ML-KEM), `lab-ssh-9` (sntrup761), `lab-ssh-8` (no
post-quantum, `ssh-rsa`) and `lab-ssh-7` (legacy).

## Not yet

- Writing SSHFP records to `netbox-plugin-dns`, RFC 2136 or other appliances
- A standalone collector that fetches from other network segments and reports through the API
- Scheduled scans of all hosts
- CNAME aliases in `known_hosts`
- SSH host certificates (`@cert-authority`)
