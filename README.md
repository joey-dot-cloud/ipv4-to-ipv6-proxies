# IPv4-to-IPv6 proxies with 3proxy

This repository contains a Bash script (`script.sh`) that:
- Generates a specified number of random IPv6 /128 addresses within your server’s on-link IPv6 subnet.
- Assigns those IPv6 addresses to a selected network interface.
- Builds a 3proxy config that exposes multiple listeners on IPv4 (one port per IPv6) and egresses traffic via the corresponding IPv6 address.
- Optionally installs and manages a systemd service for 3proxy.

Works on Debian/Ubuntu (or derivatives with `apt-get`). Root privileges are required.

### What you get
- Many HTTP or SOCKS5 proxies on IPv4 (e.g., `0.0.0.0:30000..`) that each route out via a unique IPv6 address.
- Automatic 3proxy installation (built from source) if missing.
- Safe backups of existing config files and systemd units.

## Requirements
- A Debian/Ubuntu server with global IPv6 connectivity and an on-link IPv6 subnet on your chosen interface.
- Run as root (`sudo su -` or prefix with `sudo`).
- `apt-get` available (the script installs required packages like `gcc`, `make`, `git`, `iproute2` if needed).
- Optional: `systemd` for service management.

## Quick start
Interactive run (prompts for missing values):
```bash
sudo bash script.sh
```

Non-interactive example (HTTP proxies):
```bash
sudo bash script.sh \
  -c 100 \
  -U myuser \
  -P mypass \
  -s 30000 \
  -t http
```

Non-interactive example (SOCKS5 proxies, bind to specific IPv4):
```bash
sudo bash script.sh \
  -c 50 \
  -U proxyuser \
  -P S3cure! \
  -s 40000 \
  -t socks5 \
  --bind-ipv4 127.0.0.1
```

After a successful run, if `systemd` is present and not disabled, the `3proxy` service will be enabled and started automatically.

## Usage
You can pass options or let the script prompt you:

- Interactive prompts (if missing):
  - Count of IPv6 addresses
  - Start port (default `30000`)
  - Proxy type (`http` or `socks5`; default `http`)
  - 3proxy username/password

- Legacy positional args are supported: `count user pass start_port iface`

### Options
- **-c, --count N**: Number of IPv6 addresses to generate.
- **-U, --user NAME**: 3proxy username.
- **-P, --pass PASS**: 3proxy password.
- **-s, --start-port N**: First listening port (default: `30000`).
- **-i, --iface IFACE**: Network interface to use (auto-detected if omitted).
- **--bind-ipv4 IP**: IPv4 to bind listeners (default: `0.0.0.0`).
- **--config-file PATH**: 3proxy config path (default: `/etc/3proxy.cfg`).
- **--addr-file PATH**: File storing generated IPv6 addresses (default: `/etc/3proxy.ipv6`).
- **--log-file PATH**: 3proxy log file path (default: `/var/log/3proxy.log`).
- **-t, --type TYPE**: `http` or `socks5` (default: `http`).
- **--no-service**: Skip creating/starting a `systemd` service.
- **--skip-clean**: Do not remove existing global `/128` IPv6 addresses on the interface.
- **-v, --verbose**: Verbose logs (shows per-port mapping and current IPv6 state).
- **-h, --help**: Show usage help.

### What the script does (in detail)
1. Ensures prerequisites (`iproute2`, and if needed, builds and installs 3proxy).
2. Detects the target interface and on-link IPv6 subnet (or uses `-i`).
3. Optionally removes existing global `/128` IPv6 addresses on that interface unless `--skip-clean` is set.
4. Generates `N` random IPv6 addresses (`/128`) within your subnet and adds them to the interface.
5. Writes a fresh 3proxy config that:
   - Enables `auth strong` with the provided username/password.
   - Creates one listener per IPv6 address:
     - HTTP: `proxy -6 -i<BIND_IP4> -e<IPv6> -p<port>`
     - SOCKS5: `socks -5 -6 -i<BIND_IP4> -e<IPv6> -p<port>`
6. Manages the `3proxy` service with `systemd` unless `--no-service` is used.

### Files written
- 3proxy config: `/etc/3proxy.cfg` (previous file backed up with a timestamp).
- IPv6 list: `/etc/3proxy.ipv6` (0600 permissions).
- 3proxy log: `/var/log/3proxy.log`.
- Systemd unit (if used): `/etc/systemd/system/3proxy.service` (previous file backed up).

### Service management
- Check status:
```bash
systemctl status 3proxy
```
- Logs:
```bash
journalctl -u 3proxy -xe --no-pager
```
- Restart/stop:
```bash
systemctl restart 3proxy
systemctl stop 3proxy
```
- If `--no-service` was used, run manually:
```bash
/usr/local/bin/3proxy /etc/3proxy.cfg &
```

### Notes and limits
- Ports: `start_port + count - 1` must be ≤ 65535. The script enforces this.
- IPv6 space: If your prefix has very few host bits, the script enforces availability.
- Re-runs: Existing addresses are removed unless `--skip-clean` is set. Config and unit files are backed up.
- Security: Credentials are stored in the 3proxy config; control access to the server and config file.

### Troubleshooting
- “This script must be run as root.” → Use `sudo`.
- “apt-get not found.” → Use a Debian/Ubuntu system.
- “Failed to detect an interface with a global IPv6 address.” → Ensure the server has a global IPv6 on some interface, or specify `-i`.
- “Could not determine on-link IPv6 subnet…” → Ensure proper IPv6 routing/subnet configuration.
- Service didn’t start: 
```bash
journalctl -u 3proxy -xe --no-pager
```

## Example: 10 HTTP proxies on ports 30000–30009
```bash
sudo bash script.sh -c 10 -U bot -P p@ssw0rd -s 30000 -t http
```