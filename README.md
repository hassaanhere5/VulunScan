# VulnScan — IP-Based Vulnerability & Misconfiguration Scanner

A single-file, multi-threaded Python tool that scans a target **by IP address only** and reports:

- Open TCP ports + service banners
- Missing HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- Information disclosure (Server / X-Powered-By headers)
- Insecure cookie flags (missing `Secure` / `HttpOnly`)
- Exposed sensitive files/paths (`.git/HEAD`, `.env`, `wp-config.php.bak`, `phpinfo.php`, etc.)
- Directory listing misconfiguration
- Weak/deprecated SSL & TLS protocol usage

##  Legal Notice

**Only run this against systems you own or have explicit written authorization to test.**
Unauthorized scanning is illegal under most cybercrime laws (Pakistan PECA 2016, India IT Act,
US CFAA, EU directives, etc.). This tool is for authorized penetration testing, bug bounty
programs (within scope), and personal infrastructure auditing only.

## Install

```bash
git clone https://github.com/hassaanhere5/vulnscan.git
cd vulnscan
pip install -r requirements.txt
```

`requirements.txt` just needs:
```
requests
```

## Usage

```bash
python3 vulnscan.py 192.168.1.10

python3 vulnscan.py 192.168.1.10 --ports 1-65535 --threads 300 --timeout 0.8

python3 vulnscan.py 192.168.1.10 --ports 80,443,8080,8443


python3 vulnscan.py 192.168.1.10 --output myreport.json
```

## Output

- Live colored terminal report as the scan progresses
- A full machine-readable `vulnscan_report.json` at the end, ready for further
  automation (CI pipelines, dashboards, ticketing systems, etc.)

## Roadmap / Ideas to extend

- Add UDP scanning
- Integrate a CVE database lookup for detected service banners/versions
- Add subdomain/vhost brute-forcing when a hostname is known
- Multi-target / CIDR range scanning
- HTML report export
- Rate-limiting / stealth-scan mode

## License

MIT — use responsibly.
