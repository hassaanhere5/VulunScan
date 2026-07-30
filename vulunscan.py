
import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import datetime
from urllib.parse import urljoin

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[!] Missing dependency. Run: pip install requests")
    sys.exit(1)

# ----------------------------------------------------------------------------
# Terminal colors (no external dependency needed)
# ----------------------------------------------------------------------------
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 _   _    _    ____ ____    _    _    _   _   ____ ____
| | | |  / \  / ___/ ___|  / \  | \ | | | \ | | ____/ ___|
| |_| | / _ \| |  | |     / _ \ |  \| | |  \| |  _| \___ \
|  _  |/ ___ \ |__| |___ / ___ \| |\  | | |\  | |___ ___) |
|_| |_/_/   \_\____\____/_/   \_\_| \_| |_| \_|_____|____/
{C.END}{C.BOLD}     IP-Based Vulnerability & Misconfiguration Scanner{C.END}
     {C.YELLOW}Use only on systems you are authorized to test.{C.END}
""")


# ----------------------------------------------------------------------------
# Common ports + service names (extend this dict as needed)
# ----------------------------------------------------------------------------
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "OracleDB",
    2049: "NFS", 27017: "MongoDB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 11211: "Memcached", 27018: "MongoDB-Shard"
}

# Security headers every hardened web app should send
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS -> vulnerable to SSL-stripping/downgrade attacks",
    "X-Frame-Options": "Missing -> site may be vulnerable to Clickjacking",
    "X-Content-Type-Options": "Missing -> vulnerable to MIME-sniffing attacks",
    "Content-Security-Policy": "Missing CSP -> higher XSS risk",
    "Referrer-Policy": "Missing -> may leak sensitive URL data via Referer header",
    "Permissions-Policy": "Missing -> browser features not restricted (camera/mic/geo etc.)",
    "X-XSS-Protection": "Missing (legacy but still checked) -> no browser-side XSS filter hint",
}

# Sensitive paths commonly misconfigured / exposed
SENSITIVE_PATHS = [
    ".git/HEAD", ".env", ".env.production", "wp-login.php", "wp-config.php.bak",
    "phpinfo.php", "info.php", "admin/", "administrator/", "server-status",
    ".DS_Store", "backup.zip", "backup.sql", "config.php.bak", ".htpasswd",
    "id_rsa", ".svn/entries", "web.config", "docker-compose.yml",
    "swagger.json", "api-docs", "actuator/health", ".well-known/security.txt",
]

WEAK_TLS_VERSIONS = {
    "SSLv2": ssl.PROTOCOL_TLS if hasattr(ssl, "PROTOCOL_SSLv2") else None,
}


# ----------------------------------------------------------------------------
# 1. PORT SCANNING
# ----------------------------------------------------------------------------
def scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner_text = grab_banner(s)
                return port, True, banner_text
    except Exception:
        pass
    return port, False, None


def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()[:200]
    except Exception:
        return ""


def parse_port_range(port_range):
    ports = set()
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def run_port_scan(ip, ports, threads, timeout):
    print(f"{C.BLUE}[*] Scanning {len(ports)} ports on {ip} with {threads} threads...{C.END}")
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, p, timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner_text = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports[port] = {"service": service, "banner": banner_text}
                print(f"    {C.GREEN}[OPEN]{C.END} Port {port:<6} {service:<15} {banner_text[:60] if banner_text else ''}")
    return open_ports


# ----------------------------------------------------------------------------
# 2. HTTP HEADER / SECURITY MISCONFIG CHECK
# ----------------------------------------------------------------------------
def check_http(ip, port, use_https):
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{ip}:{port}"
    findings = {"url": base_url, "reachable": False, "missing_headers": [],
                "server_banner": None, "issues": []}
    try:
        resp = requests.get(base_url, timeout=5, verify=False, allow_redirects=True)
        findings["reachable"] = True
        findings["status_code"] = resp.status_code
        headers = resp.headers

        findings["server_banner"] = headers.get("Server", "Not disclosed")
        if "Server" in headers:
            findings["issues"].append(
                f"Server header discloses software/version: '{headers['Server']}' (info disclosure)")
        if "X-Powered-By" in headers:
            findings["issues"].append(
                f"X-Powered-By header discloses backend tech: '{headers['X-Powered-By']}'")

        for h, desc in SECURITY_HEADERS.items():
            if h not in headers:
                findings["missing_headers"].append({h: desc})

        # cookie flags
        for cookie in resp.cookies:
            flags_missing = []
            if not cookie.secure:
                flags_missing.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                flags_missing.append("HttpOnly")
            if flags_missing:
                findings["issues"].append(
                    f"Cookie '{cookie.name}' missing flags: {', '.join(flags_missing)}")

    except RequestException as e:
        findings["error"] = str(e)
    return findings


# ----------------------------------------------------------------------------
# 3. SENSITIVE PATH / MISCONFIGURATION PROBING
# ----------------------------------------------------------------------------
def check_sensitive_paths(base_url):
    exposed = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path)
        try:
            r = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                exposed.append({"path": path, "status": r.status_code, "url": url})
        except RequestException:
            continue
    return exposed


def check_directory_listing(base_url):
    try:
        r = requests.get(base_url, timeout=5, verify=False)
        if "Index of /" in r.text or "<title>Directory listing for" in r.text:
            return True
    except RequestException:
        pass
    return False


# ----------------------------------------------------------------------------
# 4. SSL / TLS CHECK
# ----------------------------------------------------------------------------
def check_ssl(ip, port=443):
    result = {"valid": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cert_bin = ssock.getpeercert(binary_form=True)
                result["valid"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()
                if result["protocol"] in ("SSLv3", "TLSv1", "TLSv1.1"):
                    result["weak_protocol"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


# ----------------------------------------------------------------------------
# REPORT GENERATION
# ----------------------------------------------------------------------------
def print_section(title):
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}\n{title}\n{'=' * 60}{C.END}")


def build_report(ip, open_ports, http_findings, ssl_findings, exposed_paths, dir_listing):
    return {
        "target": ip,
        "scan_time": datetime.datetime.now().isoformat(),
        "open_ports": open_ports,
        "http_findings": http_findings,
        "ssl_findings": ssl_findings,
        "exposed_sensitive_paths": exposed_paths,
        "directory_listing_enabled": dir_listing,
    }


# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
def main():
    requests.packages.urllib3.disable_warnings()  # self-signed certs are common on scan targets

    parser = argparse.ArgumentParser(description="Advanced IP-based Vulnerability Scanner")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--ports", default="1-1024", help="Port range, e.g. 1-1024 or 80,443,8080")
    parser.add_argument("--threads", type=int, default=150, help="Thread count for port scan")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout (seconds)")
    parser.add_argument("--output", default="vulnscan_report.json", help="JSON report output file")
    args = parser.parse_args()

    banner()
    print(f"{C.YELLOW}[!] Legal reminder: only scan systems you own or are authorized to test.{C.END}\n")

    ip = args.ip
    ports = parse_port_range(args.ports)

    print_section(f"PORT SCAN - {ip}")
    open_ports = run_port_scan(ip, ports, args.threads, args.timeout)
    if not open_ports:
        print(f"{C.RED}[-] No open ports found in given range.{C.END}")

    http_findings = []
    exposed_paths = []
    dir_listing = False
    ssl_findings = {}

    web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443) or "HTTP" in open_ports[p]["service"]]

    if not web_ports and open_ports:
        # nothing http-like detected among common web ports; still nothing to probe
        pass

    for port in web_ports:
        use_https = port in (443, 8443)
        print_section(f"HTTP CHECK - port {port} ({'https' if use_https else 'http'})")
        result = check_http(ip, port, use_https)
        http_findings.append(result)

        if result.get("reachable"):
            print(f"    Status: {result.get('status_code')}  Server: {result.get('server_banner')}")
            for issue in result["issues"]:
                print(f"    {C.YELLOW}[WARN]{C.END} {issue}")
            for mh in result["missing_headers"]:
                for h, desc in mh.items():
                    print(f"    {C.RED}[MISSING HEADER]{C.END} {h}: {desc}")

            base_url = result["url"]
            print(f"    {C.BLUE}[*] Probing sensitive paths...{C.END}")
            paths = check_sensitive_paths(base_url)
            exposed_paths.extend(paths)
            for p in paths:
                print(f"    {C.RED}[EXPOSED]{C.END} {p['url']} (HTTP {p['status']})")

            if check_directory_listing(base_url):
                dir_listing = True
                print(f"    {C.RED}[MISCONFIG]{C.END} Directory listing appears to be enabled")

        if use_https:
            print_section(f"SSL/TLS CHECK - port {port}")
            ssl_result = check_ssl(ip, port)
            ssl_findings[port] = ssl_result
            if ssl_result.get("valid"):
                proto = ssl_result.get("protocol")
                print(f"    Protocol: {proto}   Cipher: {ssl_result.get('cipher')}")
                if ssl_result.get("weak_protocol"):
                    print(f"    {C.RED}[VULN]{C.END} Weak/deprecated TLS protocol in use: {proto}")
            else:
                print(f"    {C.YELLOW}[!] Could not establish SSL session: {ssl_result.get('error')}{C.END}")

    # ------------------------------------------------------------------
    print_section("SUMMARY")
    total_issues = sum(len(h.get("issues", [])) + len(h.get("missing_headers", [])) for h in http_findings)
    total_issues += len(exposed_paths) + (1 if dir_listing else 0)
    total_issues += sum(1 for s in ssl_findings.values() if s.get("weak_protocol"))

    print(f"Open ports found      : {len(open_ports)}")
    print(f"Web services checked   : {len(web_ports)}")
    print(f"Sensitive files exposed: {len(exposed_paths)}")
    print(f"Directory listing      : {'YES - VULNERABLE' if dir_listing else 'No'}")
    print(f"Total flagged issues   : {C.BOLD}{total_issues}{C.END}")

    report = build_report(ip, open_ports, http_findings, ssl_findings, exposed_paths, dir_listing)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n{C.GREEN}[+] Full JSON report saved to: {args.output}{C.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Scan interrupted by user.{C.END}")
        sys.exit(1)