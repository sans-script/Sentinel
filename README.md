# Sentinel

A small, dependency-light monitor for servers that run Node apps under **PM2** behind **Nginx**. It checks each target over HTTP, then connects over SSH with a read-only set of commands to report CPU, memory, disk, PM2 processes and the busiest Nginx routes, and shows everything in a single-page dashboard.

It is meant as a base you can point at any group of hosts: one Python file, one HTML file, a JSON list of targets.

## What it does

- **HTTP checks** for every target: availability, latency and a readable reason when it is down (TLS error, timeout, refused).
- **SSH telemetry** for targets of type `vm`: CPU load, RAM, root disk, PM2 process list and the top Nginx routes.
- **Dashboard** with live status, a side panel per VM with PM2 processes and the latest logs, and an on-demand refresh.
- **Safe defaults**: it listens on `127.0.0.1`, refuses to listen elsewhere without an access token, and refuses SSH hosts it does not know.

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip
cp config/sites.example.json config/sites.json  # then edit it
cp config/.env.example config/.env              # then edit it
.venv/bin/python sentinel.py
```

Open `http://127.0.0.1:8000`. With no `config/sites.json`, the example targets are used so you can see the dashboard.

## Configuration

### Targets: `config/sites.json`

```json
[
  { "name": "Public website", "url": "https://example.com", "ip": "-", "hostname": "example.com", "type": "http", "size": "hero" },
  { "name": "Web app", "url": "https://app.example.com/", "ip": "192.0.2.10", "hostname": "web-01", "user": "monitor", "type": "vm", "size": "highlight" }
]
```

| Field | Meaning |
| --- | --- |
| `type` | `http` checks only the URL. `vm` also runs the SSH telemetry on `ip`. |
| `ip` | Address to SSH into (`-` for `http` targets). Several targets can share one VM; it is queried once per cycle. |
| `hostname` | Name shown for the host. Useful when the URL goes through a proxy or CDN. |
| `user` | SSH user for this target. Defaults to `SSH_USER`. |
| `size` | Card size on the dashboard: `hero`, `highlight` or `small`. |

`config/sites.json` is ignored by git, so your real inventory never reaches the repository.

### Environment: `config/.env`

See [`config/.env.example`](config/.env.example) for every option. The important ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SERVER_HOST` | `127.0.0.1` | Listen address. Any other value requires `SENTINEL_API_TOKEN`. |
| `SENTINEL_API_TOKEN` | empty | Protects the dashboard and `/api/*`. |
| `SSH_PRIVATE_KEY` or `SSH_KEY_BASE64` | none | The key used for telemetry. Kept in memory only. |
| `SSH_HOST_KEY_POLICY` | `strict` | `strict` refuses unknown hosts, `accept-new` trusts them on first contact. |
| `SSH_USER`, `SSH_TIMEOUT`, `MAX_SSH_WORKERS` | `monitor`, `10`, `3` | SSH behaviour. |
| `INTERVAL_SECONDS` | `60` | Time between cycles. |

With `SSH_HOST_KEY_POLICY=strict`, add the hosts to your `known_hosts` first (for example `ssh-keyscan -H 192.0.2.10 >> ~/.ssh/known_hosts`), or point `SSH_KNOWN_HOSTS` at a file.

## What it runs on your servers

Sentinel only runs the read-only commands below, so you can review them before giving it a key.

Every cycle:

| Command | Purpose |
| --- | --- |
| `hostname`, `nproc`, `cat /proc/loadavg` | Host name, vCPUs, load average |
| `free -m`, `df -h /` | Memory and root disk usage |
| `which pm2`, `pm2 jlist` | PM2 processes of the SSH user |
| `sudo -n env pm2 jlist` | PM2 processes running as root |
| `awk`/`sort`/`uniq` over the Nginx access log, with `sudo -n` | Four most requested routes |

On demand, when you open a VM panel: `pm2 logs --lines 35 --nostream`, with the `sudo -n` fallback.

The `sudo -n` commands need a rule that allows only those binaries for the monitoring user:

```text
monitor ALL=(ALL) NOPASSWD: /usr/bin/pm2, /usr/bin/awk
```

Do not grant `NOPASSWD: ALL`: that would make the monitoring key equivalent to root on every host. Even with the rule above, `pm2` and `awk` can run arbitrary code as root, so use a dedicated key, restrict it to the monitoring host with `from=` in `authorized_keys`, and treat it as sensitive.

## Security notes

- The dashboard shows the state of every host and the latest PM2 logs. Always set a token before exposing it, and put it behind HTTPS (a reverse proxy) when it leaves your machine.
- Logs can contain secrets. Check what your apps print before you expose the log panel.
- Keep the real `config/sites.json` and `config/.env` out of git. The `.gitignore` already does.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```
