import time
import concurrent.futures
import warnings
import urllib3
import urllib.parse
import requests
import threading
import http.server
import socketserver
import json
import os
import io
import base64
import paramiko
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_dotenv_file(filepath: str):
    """Load environment variables, supporting escaped newlines, multi-line values and comments."""
    if not os.path.exists(filepath):
        return
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith("#") or "=" not in line:
            i += 1
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()

        if (val.startswith('"') and not (val.endswith('"') and len(val) > 1)) or           (val.startswith("'") and not (val.endswith("'") and len(val) > 1)):
            quote_char = val[0]
            val_lines = [val[1:]]
            i += 1
            while i < len(lines):
                cur_line = lines[i]
                if cur_line.rstrip().endswith(quote_char):
                    val_lines.append(cur_line.rstrip()[:-1])
                    break
                else:
                    val_lines.append(cur_line)
                i += 1
            val = "\n".join(val_lines)
        else:
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            else:
                val = val.split('#')[0].strip()

        val = val.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t')
        if key:
            os.environ[key] = val
        i += 1

for env_path in [os.path.join(BASE_DIR, ".env"), os.path.join(BASE_DIR, "config", ".env")]:
    if os.path.exists(env_path):
        load_dotenv_file(env_path)

SERVER_HOST = os.environ.get("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("SENTINEL_PORT", 8000))
INTERVAL_SECONDS = int(os.environ.get("INTERVAL_SECONDS", 60))
MAX_SSH_WORKERS = int(os.environ.get("MAX_SSH_WORKERS", 3))
SSH_TIMEOUT = int(os.environ.get("SSH_TIMEOUT", 10))
SSH_DEFAULT_USER = os.environ.get("SSH_USER", "monitor")
SENTINEL_API_TOKEN = os.environ.get("SENTINEL_API_TOKEN", "").strip()
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() in ("true", "1")
SSH_HOST_KEY_POLICY = os.environ.get("SSH_HOST_KEY_POLICY", "strict").strip().lower()
SSH_KNOWN_HOSTS = os.environ.get("SSH_KNOWN_HOSTS", "").strip()

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def exposure_error(host: str, token: str) -> Optional[str]:
    """The dashboard shows the state of every host, so it must not be reachable without a token."""
    if host not in LOOPBACK_HOSTS and not token:
        return (
            f"SERVER_HOST={host} exposes the dashboard beyond this machine; "
            "set SENTINEL_API_TOKEN first, or bind to 127.0.0.1."
        )
    return None


def build_host_key_policy(name: str) -> paramiko.MissingHostKeyPolicy:
    """strict refuses unknown hosts (default); accept-new trusts a host on first contact."""
    if name == "accept-new":
        return paramiko.AutoAddPolicy()
    if name == "strict":
        return paramiko.RejectPolicy()
    raise ValueError("SSH_HOST_KEY_POLICY must be 'strict' or 'accept-new'")


RATE_LIMIT_LOGS: Dict[str, List[float]] = {}
RATE_LIMIT_LOCK = threading.Lock()

def check_rate_limit(client_ip: str, max_reqs: int = 10, window_sec: float = 60.0) -> bool:
    now = time.time()
    with RATE_LIMIT_LOCK:
        timestamps = RATE_LIMIT_LOGS.get(client_ip, [])
        timestamps = [t for t in timestamps if now - t < window_sec]
        if len(timestamps) >= max_reqs:
            RATE_LIMIT_LOGS[client_ip] = timestamps
            return True
        timestamps.append(now)
        RATE_LIMIT_LOGS[client_ip] = timestamps
        return False

def load_ssh_key() -> Optional[paramiko.PKey]:
    """
    Load the private key from the environment:
    - SSH_PRIVATE_KEY (plain text, or with escaped newlines)
    - SSH_KEY_BASE64 (base64-encoded key)
    """
    key_classes = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
    if hasattr(paramiko, "DSSKey"):
        key_classes.append(paramiko.DSSKey)

    raw_key = os.environ.get("SSH_PRIVATE_KEY", "").strip()
    if raw_key:
        if "\\n" in raw_key:
            raw_key = raw_key.replace("\\n", "\n")
        for key_class in key_classes:
            try:
                return key_class.from_private_key(io.StringIO(raw_key))
            except Exception:
                continue

    b64_key = os.environ.get("SSH_KEY_BASE64", "").strip()
    if b64_key:
        try:
            decoded = base64.b64decode(b64_key).decode("utf-8")
            for key_class in key_classes:
                try:
                    return key_class.from_private_key(io.StringIO(decoded))
                except Exception:
                    continue
        except Exception:
            pass

    return None

SSH_PKEY = load_ssh_key()
if not SSH_PKEY:
    print("[!] No valid SSH key found (set SSH_PRIVATE_KEY or SSH_KEY_BASE64); VM telemetry is disabled.")

def connect_ssh(vm_ip: str, user: str = "monitor", timeout: int = 5) -> paramiko.SSHClient:
    """Connect with the private key held in memory from the environment; nothing is read from ~/.ssh."""
    if not SSH_PKEY:
        raise ValueError("SSH private key missing or invalid (SSH_PRIVATE_KEY).")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if SSH_KNOWN_HOSTS:
        client.load_host_keys(SSH_KNOWN_HOSTS)
    client.set_missing_host_key_policy(build_host_key_policy(SSH_HOST_KEY_POLICY))

    client.connect(
        hostname=vm_ip,
        username=user,
        pkey=SSH_PKEY,
        timeout=timeout,
        banner_timeout=timeout,
        look_for_keys=False,
        allow_agent=False
    )
    return client

SITES_PATH_CANDIDATES = [
    os.path.join(BASE_DIR, "config", "sites.json"),
    os.path.join(BASE_DIR, "sites.json"),
    os.path.join(BASE_DIR, "config", "sites.example.json"),
]
SITES_PATH = next((p for p in SITES_PATH_CANDIDATES if os.path.exists(p)), SITES_PATH_CANDIDATES[0])

with open(SITES_PATH, encoding="utf-8") as _f:
    SITES = json.load(_f)

MONITOR_TARGETS = SITES

@dataclass
class PM2App:
    name: str
    status: str
    pid: Optional[int] = None
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    restarts: int = 0
    uptime_ms: int = 0
    mode: str = "fork"

@dataclass
class CheckResult:
    name: str
    url: str
    ip: str
    vm_ip: Optional[str]
    hostname: str
    is_online: bool
    latency_ms: int
    status_label: str
    error_msg: str = ""
    pm2_installed: bool = False
    apps: List[PM2App] = field(default_factory=list)
    hardware: Optional[dict] = None
    check_type: str = "http"
    status_cls: str = "status-up"
    size: str = "highlight"
    user: str = "monitor"

LATEST_RESULTS: List[CheckResult] = []
RESULTS_LOCK = threading.Lock()
LAST_UPDATE_TIME = ""
VM_CACHE: Dict[str, dict] = {}
VM_CACHE_LOCK = threading.Lock()
FAILURE_COUNTS: Dict[str, int] = {}

def query_vm_ssh(vm_ip: str, user: str = "monitor") -> dict:
    with VM_CACHE_LOCK:
        if vm_ip in VM_CACHE:
            return VM_CACHE[vm_ip]

    t0 = time.perf_counter()
    cmd_str = (
        "export PATH=$PATH:/usr/local/bin:$(find ~/.nvm/versions/node -maxdepth 2 -name bin 2>/dev/null | tail -n 1); "
        "echo HOSTNAME: $(hostname 2>/dev/null); "
        "echo CPU_CORES: $(nproc 2>/dev/null || echo 1); "
        "echo LOAD_AVG: $(cat /proc/loadavg 2>/dev/null | awk '{print $1}' || echo 0); "
        "echo '===MEM==='; free -m 2>/dev/null || echo ''; "
        "echo '===DISK==='; df -h / 2>/dev/null | tail -n 1 || echo ''; "
        "echo '===TOP_ROUTES==='; sudo -n awk -F'\"' '{print $2}' /var/log/nginx/access.log 2>/dev/null | awk '{print $1, $2}' | cut -d? -f1 | sort | uniq -c | sort -rn | head -n 4 || echo ''; "
        "echo PM2_PATH: $(which pm2 2>/dev/null || echo NONE); "
        "echo '===USER_PM2==='; PM2_SILENT=true pm2 jlist 2>/dev/null || echo '[]'; "
        "echo '===ROOT_PM2==='; sudo -n env PM2_SILENT=true pm2 jlist 2>/dev/null || echo '[]';"
    )

    try:
        client = connect_ssh(vm_ip, user=user, timeout=5)
        stdin, stdout, stderr = client.exec_command(cmd_str, timeout=6)
        out = stdout.read().decode('utf-8', errors='ignore')
        client.close()
        latency = int((time.perf_counter() - t0) * 1000)

        hostname = ""
        pm2_path = "NONE"
        cpu_cores = 1
        load_avg = 0.0
        ram_total = 0
        ram_used = 0
        ram_pct = 0
        disk_free = "-"
        disk_pct = 0
        top_routes = []

        lines = out.splitlines()
        in_mem = False
        in_disk = False
        in_routes = False

        for line in lines:
            line_s = line.strip()
            if line_s.startswith('HOSTNAME:'):
                hostname = line_s.split('HOSTNAME:')[1].strip()
            elif line_s.startswith('CPU_CORES:'):
                try: cpu_cores = int(line_s.split('CPU_CORES:')[1].strip())
                except: pass
            elif line_s.startswith('LOAD_AVG:'):
                try: load_avg = float(line_s.split('LOAD_AVG:')[1].strip())
                except: pass
            elif line_s == '===MEM===':
                in_mem = True
                in_disk = False
                in_routes = False
                continue
            elif line_s == '===DISK===':
                in_mem = False
                in_disk = True
                in_routes = False
                continue
            elif line_s == '===TOP_ROUTES===':
                in_mem = False
                in_disk = False
                in_routes = True
                continue
            elif line_s.startswith('PM2_PATH:') or line_s.startswith('===USER_PM2==='):
                in_mem = False
                in_disk = False
                in_routes = False
                if line_s.startswith('PM2_PATH:'):
                    pm2_path = line_s.split('PM2_PATH:')[1].strip()
                continue
            elif line_s.startswith('===ROOT_PM2==='):
                in_mem = False
                in_disk = False
                in_routes = False
                continue

            if in_mem and ('Mem:' in line_s or 'Memória:' in line_s or line_s.startswith('Mem')):
                parts = line_s.split()
                if len(parts) >= 3:
                    try:
                        ram_total = int(parts[1])
                        ram_used = int(parts[2])
                        ram_pct = int(round((ram_used / ram_total) * 100)) if ram_total > 0 else 0
                    except: pass
            elif in_disk and ('/' in line_s):
                parts = line_s.split()
                if len(parts) >= 5:
                    try:
                        disk_free = parts[3]
                        disk_pct_str = parts[4].replace('%', '')
                        disk_pct = int(disk_pct_str)
                    except: pass
            elif in_routes and line_s:
                parts = line_s.split(None, 2)
                if len(parts) >= 3:
                    count_str, method, path = parts[0], parts[1], parts[2]
                    try:
                        top_routes.append({
                            "count": int(count_str),
                            "method": method,
                            "path": path
                        })
                    except: pass

        user_pm2_str = ""
        root_pm2_str = ""
        if '===USER_PM2===' in out:
            part = out.split('===USER_PM2===')[1]
            if '===ROOT_PM2===' in part:
                user_pm2_str = part.split('===ROOT_PM2===')[0].strip()
                root_pm2_str = part.split('===ROOT_PM2===')[1].strip()
            else:
                user_pm2_str = part.strip()

        raw_apps = []
        for json_str in [user_pm2_str, root_pm2_str]:
            if not json_str or json_str == '[]':
                continue
            try:
                data = json.loads(json_str)
                if isinstance(data, list):
                    raw_apps.extend(data)
            except:
                start = json_str.find('[')
                end = json_str.rfind(']')
                if start != -1 and end != -1:
                    try:
                        data = json.loads(json_str[start:end+1])
                        if isinstance(data, list):
                            raw_apps.extend(data)
                    except:
                        pass

        apps = []
        seen_names = set()
        for item in raw_apps:
            if not isinstance(item, dict):
                continue
            app_name = item.get("name", "unknown")
            if app_name in seen_names:
                continue
            seen_names.add(app_name)

            pm2_env = item.get("pm2_env", {}) or {}
            monit = item.get("monit", {}) or {}
            status = pm2_env.get("status", "unknown")
            pid = item.get("pid")
            mode = pm2_env.get("exec_mode", "fork_mode")
            if "cluster" in mode.lower():
                mode = "cluster"
            else:
                mode = "fork"

            mem_bytes = monit.get("memory", 0) or 0
            mem_mb = round(mem_bytes / (1024 * 1024), 1)
            cpu_val = round(float(monit.get("cpu", 0.0) or 0.0), 1)
            restarts = pm2_env.get("restart_time", 0) or 0
            pm_uptime = pm2_env.get("pm_uptime", 0) or 0

            apps.append(PM2App(
                name=app_name,
                status=status,
                pid=pid,
                memory_mb=mem_mb,
                cpu_percent=cpu_val,
                restarts=restarts,
                uptime_ms=pm_uptime,
                mode=mode
            ))

        pm2_installed = pm2_path != "NONE" or len(apps) > 0

        load_pct = int(round((load_avg / cpu_cores) * 100)) if cpu_cores > 0 else 0
        hardware_info = {
            "cpu_cores": cpu_cores,
            "load_avg": load_avg,
            "load_pct": load_pct,
            "ram_total_mb": ram_total,
            "ram_used_mb": ram_used,
            "ram_used_pct": ram_pct,
            "disk_free": disk_free,
            "disk_used_pct": disk_pct,
            "top_routes": top_routes
        }

        res = {
            "is_online": True,
            "latency_ms": latency,
            "hostname": hostname,
            "status_label": "ONLINE",
            "error_msg": "",
            "pm2_installed": pm2_installed,
            "apps": apps,
            "hardware": hardware_info
        }

    except Exception:
        latency = int((time.perf_counter() - t0) * 1000)
        res = {
            "is_online": False,
            "latency_ms": latency,
            "hostname": "",
            "status_label": "OFFLINE",
            "error_msg": "SSH connection to the VM failed",
            "pm2_installed": False,
            "apps": [],
            "hardware": None
        }

    with VM_CACHE_LOCK:
        VM_CACHE[vm_ip] = res
    return res

LOG_CACHE: Dict[str, dict] = {}
LOG_CACHE_LOCK = threading.Lock()

def fetch_vm_logs(vm_ip: str, user: str = "monitor", lines: int = 35) -> str:
    cache_key = f"{vm_ip}_{lines}"
    now = time.time()
    with LOG_CACHE_LOCK:
        if cache_key in LOG_CACHE:
            cached = LOG_CACHE[cache_key]
            if now - cached["time"] < 8.0:
                return cached["logs"]

    cmd_str = (
        "export PATH=$PATH:/usr/local/bin:$(find ~/.nvm/versions/node -maxdepth 2 -name bin 2>/dev/null | tail -n 1); "
        f"pm2 logs --lines {lines} --nostream 2>/dev/null || "
        f"sudo -n env PATH=$PATH pm2 logs --lines {lines} --nostream 2>/dev/null || "
        "echo 'No logs available right now, or PM2 is not set up.'"
    )

    try:
        client = connect_ssh(vm_ip, user=user, timeout=5)
        stdin, stdout, stderr = client.exec_command(cmd_str, timeout=8)
        out = stdout.read().decode('utf-8', errors='ignore').strip()
        client.close()
        logs_res = out if out else "Nenhum registro de log retornado pelo PM2."
    except Exception:
        logs_res = "Could not collect the logs over SSH right now."

    with LOG_CACHE_LOCK:
        LOG_CACHE[cache_key] = {"logs": logs_res, "time": now}
    return logs_res

def check_item(target: dict) -> CheckResult:
    name = target["name"]
    url = target.get("url", "")
    ip = target.get("ip", "")
    hostname = target.get("hostname", "")
    is_vm = target.get("type") == "vm"
    user = target.get("user", "monitor")

    http_ok = True
    http_label = "ONLINE"
    http_error = ""

    t0 = time.perf_counter()

    if url and url.startswith("http"):
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        try:
            r = session.get(url, timeout=6, verify=VERIFY_SSL, allow_redirects=True, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'pt-BR,pt;q=0.9',
                'Connection': 'close'
            })
            http_code = r.status_code
            if r.status_code < 400:
                http_ok = True
                http_label = "ONLINE"
                http_error = ""
            elif r.status_code == 403:
                http_ok = True
                http_label = "ONLINE"
                http_error = f"HTTP 403 (WAF / Cloudflare)"
            else:
                http_ok = False
                http_label = f"HTTP {r.status_code}"
                http_error = f"HTTP {r.status_code} {r.reason or 'Erro no Servidor'}"
        except requests.exceptions.SSLError:
            http_ok = False
            http_label = "SSL_ERROR"
            http_error = "Invalid or expired TLS/SSL certificate"
        except requests.exceptions.Timeout:
            http_ok = False
            http_label = "TIMEOUT"
            http_error = "Connection timed out (>6s)"
        except requests.exceptions.ConnectionError:
            http_ok = False
            http_label = "CONN_REFUSED"
            http_error = "Connection refused or server unreachable"
        except Exception:
            http_ok = False
            http_label = "ERRO_HTTP"
            http_error = "HTTP communication failed"
        finally:
            session.close()

    vm_data = {"is_online": True, "latency_ms": 0, "status_label": "ONLINE", "error_msg": "", "pm2_installed": False, "apps": []}
    if is_vm and ip and ip != "-":
        vm_data = query_vm_ssh(ip, user=user)
        if not vm_data["is_online"]:
            http_ok = False
            http_label = "VM OFFLINE"
            http_error = vm_data["error_msg"]

    latency = int((time.perf_counter() - t0) * 1000)
    if is_vm and vm_data.get("latency_ms"):
        latency = vm_data["latency_ms"]

    if http_ok:
        FAILURE_COUNTS[name] = 0
        is_online = True
        status_cls = "status-up"
        final_status_label = "ONLINE"
        final_error_msg = http_error
    else:
        fails = FAILURE_COUNTS.get(name, 0) + 1
        FAILURE_COUNTS[name] = fails
        is_online = False
        if fails == 1:
            status_cls = "status-warning"
            final_status_label = "UNSTABLE"
            final_error_msg = http_error or "Instabilidade na rota HTTP"
        else:
            status_cls = "status-down"
            final_status_label = "OFFLINE"
            final_error_msg = http_error or "HTTP service unreachable"

    size = target.get("size", "highlight")

    return CheckResult(
        name=name,
        url=url,
        ip=ip,
        vm_ip=ip if is_vm else None,
        hostname=vm_data.get("hostname") or hostname,
        is_online=is_online,
        latency_ms=latency,
        status_label=final_status_label,
        error_msg=final_error_msg,
        pm2_installed=vm_data.get("pm2_installed", False),
        apps=vm_data.get("apps", []),
        hardware=vm_data.get("hardware"),
        check_type="vm" if is_vm else "http",
        status_cls=status_cls,
        size=size,
        user=user
    )

DASHBOARD_PATH_CANDIDATES = [
    os.path.join(BASE_DIR, "web", "dashboard.html"),
    os.path.join(BASE_DIR, "templates", "dashboard.html"),
    os.path.join(BASE_DIR, "dashboard.html"),
]
DASHBOARD_PATH = next((p for p in DASHBOARD_PATH_CANDIDATES if os.path.exists(p)), DASHBOARD_PATH_CANDIDATES[0])

with open(DASHBOARD_PATH, encoding="utf-8") as _html_f:
    DASHBOARD_HTML = _html_f.read()

class SentinelHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SentinelServer/2.0"
    sys_version = ""

    def is_authenticated(self, parsed_url) -> bool:
        if not SENTINEL_API_TOKEN:
            return True

        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ', 1)[1].strip()
            if token == SENTINEL_API_TOKEN:
                return True

        params = urllib.parse.parse_qs(parsed_url.query)
        query_token = params.get('token', [''])[0].strip()
        if query_token and query_token == SENTINEL_API_TOKEN:
            return True

        cookie_header = self.headers.get('Cookie', '')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    k, v = cookie.strip().split('=', 1)
                    if k == 'sentinel_token' and v == SENTINEL_API_TOKEN:
                        return True

        return False

    def send_security_headers(self, content_type: str = 'application/json; charset=utf-8'):
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')

        req_origin = self.headers.get('Origin', '').strip()
        if req_origin and req_origin in ALLOWED_ORIGINS:
            self.send_header('Access-Control-Allow-Origin', req_origin)
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')

        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        client_ip = self.client_address[0]

        if path in ('/', '/index.html'):
            self.send_response(200)
            self.send_security_headers('text/html; charset=utf-8')
            try:
                with open(DASHBOARD_PATH, encoding="utf-8") as _html_f:
                    html_content = _html_f.read().encode('utf-8')
            except Exception:
                html_content = DASHBOARD_HTML.encode('utf-8')
            self.wfile.write(html_content)
            return

        if path == '/api/status':
            if not self.is_authenticated(parsed):
                self.send_response(401)
                self.send_security_headers('application/json; charset=utf-8')
                self.wfile.write(b'{"error": "Unauthorized", "message": "Token de autenticacao ausente ou invalido."}')
                return

            self.send_response(200)
            self.send_security_headers('application/json; charset=utf-8')
            with RESULTS_LOCK:
                data = {
                    "updated_at": LAST_UPDATE_TIME,
                    "results": [asdict(r) for r in LATEST_RESULTS]
                }
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
            return

        if path == '/api/logs':
            if not self.is_authenticated(parsed):
                self.send_response(401)
                self.send_security_headers('application/json; charset=utf-8')
                self.wfile.write(b'{"error": "Unauthorized", "message": "Token de autenticacao ausente ou invalido."}')
                return

            if check_rate_limit(client_ip, max_reqs=8, window_sec=60.0):
                self.send_response(429)
                self.send_security_headers('application/json; charset=utf-8')
                self.wfile.write(b'{"error": "Too Many Requests", "message": "Limite de consultas de logs excedido. Aguarde um minuto."}')
                return

            params = urllib.parse.parse_qs(parsed.query)
            target_name = params.get('name', [''])[0]

            matched = None
            for t in MONITOR_TARGETS:
                if target_name and t["name"] == target_name:
                    matched = t
                    break

            if matched and matched.get("type") == "vm" and matched.get("ip"):
                logs_out = fetch_vm_logs(matched["ip"], user=matched.get("user", "monitor"), lines=35)
                resp = {
                    "success": True,
                    "name": matched["name"],
                    "ip": matched["ip"],
                    "has_pm2": True,
                    "logs": logs_out
                }
            else:
                resp = {
                    "success": False,
                    "name": target_name,
                    "has_pm2": False,
                    "logs": "Endpoint HTTP externo (sem servidor SSH ou PM2 vinculado)."
                }

            self.send_response(200)
            self.send_security_headers('application/json; charset=utf-8')
            self.wfile.write(json.dumps(resp, ensure_ascii=False).encode('utf-8'))
            return

        self.send_response(404)
        self.send_security_headers('text/plain; charset=utf-8')
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        self.send_response(405)
        self.send_security_headers('text/plain; charset=utf-8')
        self.wfile.write(b"405 Method Not Allowed")

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass

def start_server():
    server = socketserver.ThreadingTCPServer((SERVER_HOST, SERVER_PORT), SentinelHandler)
    server.allow_reuse_address = True
    print(f"[+] Dashboard listening on http://{SERVER_HOST}:{SERVER_PORT}/")
    server.serve_forever()

def run_single_cycle():

    vm_targets = [t for t in MONITOR_TARGETS if t.get("type") == "vm"]
    unique_vms = {}
    for t in vm_targets:
        ip = t["ip"]
        user = t.get("user", "monitor")
        unique_vms[ip] = user

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SSH_WORKERS) as vm_executor:
        future_vms = {vm_executor.submit(query_vm_ssh, ip, user): ip for ip, user in unique_vms.items()}
        for f in concurrent.futures.as_completed(future_vms):
            pass

    item_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        future_items = {executor.submit(check_item, s): s["name"] for s in MONITOR_TARGETS}
        for f in concurrent.futures.as_completed(future_items):
            try:
                res = f.result()
                item_results[res.name] = res
            except Exception:
                pass

    final_results = []
    for t in MONITOR_TARGETS:
        if t["name"] in item_results:
            final_results.append(item_results[t["name"]])
        else:
            final_results.append(check_item(t))

    return final_results

def main():
    global LATEST_RESULTS, LAST_UPDATE_TIME, VM_CACHE

    unique_vms_count = len({t["ip"] for t in MONITOR_TARGETS if t.get("type") == "vm"})
    auth_mode = "SSH key" if SSH_PKEY else "none (set SSH_PRIVATE_KEY)"
    problem = exposure_error(SERVER_HOST, SENTINEL_API_TOKEN)
    if problem:
        raise SystemExit(f"[!] {problem}")
    print("=" * 65)
    print("SENTINEL - VM AND SERVICE MONITORING")
    print(f"Targets: {len(MONITOR_TARGETS)} | Unique VMs: {unique_vms_count}")
    print(f"SSH authentication: {auth_mode}")
    print(f"SSH workers: {MAX_SSH_WORKERS} (timeout {SSH_TIMEOUT}s) | interval: {INTERVAL_SECONDS}s")
    print(f"HTTP port: {SERVER_PORT}")
    print("=" * 65)

    threading.Thread(target=start_server, daemon=True).start()

    while True:
        try:
            t0 = time.time()
            with VM_CACHE_LOCK:
                VM_CACHE.clear()

            current_results = run_single_cycle()

            for res in current_results:
                apps_info = f"({len(res.apps)} PM2 apps)" if res.apps else ""
                host_str = f"{res.user}@{res.vm_ip}" if res.vm_ip else (f"{res.user}@{res.hostname}" if res.hostname and res.hostname != "-" else "-")
                print(f"[{res.status_label:^10}] {res.name:<28} | {host_str:<26} | {res.latency_ms:>4}ms {apps_info}")

            with RESULTS_LOCK:
                LATEST_RESULTS = current_results
                LAST_UPDATE_TIME = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            elapsed = time.time() - t0
            print(f"--> Cycle finished in {elapsed:.2f}s. Next check in {INTERVAL_SECONDS}s.\n")
            time.sleep(INTERVAL_SECONDS)

        except KeyboardInterrupt:
            print("\nSentinel stopped.")
            break
        except Exception as e:
            print(f"[!] Error in the main loop: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()
