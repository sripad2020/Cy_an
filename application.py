import os
import socket
import ssl
import logging
from datetime import datetime
from urllib.parse import urlparse
import requests
import whois
import dns.resolver
import shodan
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

app = FastAPI(title="CyberSentry X", version="2.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Jinja2 template setup
templates_env = Environment(loader=FileSystemLoader("templates"))

# API Keys from .env
VT_API_KEY = os.getenv('VT_API_KEY', '')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
SAFE_BROWSING_API_KEY = os.getenv('SAFE_BROWSING_API_KEY', '')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Request Model ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    template = templates_env.get_template("index.html")
    return template.render()


@app.post("/scan")
async def scan(req: ScanRequest):
    """Unified scan endpoint: accepts a URL/domain and runs all scans."""
    target = req.url.strip()
    if not target:
        return JSONResponse({'error': 'No URL provided'}, status_code=400)

    domain = extract_domain(target)
    full_url = ensure_url(target)

    if not domain:
        return JSONResponse({'error': 'Invalid URL or domain'}, status_code=400)

    results = {
        'target': target,
        'domain': domain,
        'url': full_url,
        'timestamp': datetime.utcnow().isoformat(),
        'phishing': {},
        'network': {},
        'vulnerability': {}
    }

    # ── Phishing Detection ──
    try:
        results['phishing']['safe_browsing'] = check_safe_browsing(full_url)
    except Exception as e:
        results['phishing']['safe_browsing'] = {'error': str(e)}

    try:
        results['phishing']['domain_info'] = check_domain_age(domain)
    except Exception as e:
        results['phishing']['domain_info'] = {'error': str(e)}

    # ── Network Analysis ──
    try:
        results['network']['dns'] = dns_lookup(domain)
    except Exception as e:
        results['network']['dns'] = {'error': str(e)}

    try:
        results['network']['ssl'] = check_ssl_certificate(domain)
    except Exception as e:
        results['network']['ssl'] = {'error': str(e)}

    try:
        results['network']['headers'] = check_security_headers(full_url)
    except Exception as e:
        results['network']['headers'] = {'error': str(e)}

    try:
        results['network']['ports'] = basic_port_scan(domain)
    except Exception as e:
        results['network']['ports'] = {'error': str(e)}

    try:
        results['network']['tech_stack'] = detect_technology(full_url)
    except Exception as e:
        results['network']['tech_stack'] = {'error': str(e)}

    try:
        results['network']['cookies'] = audit_cookies(full_url)
    except Exception as e:
        results['network']['cookies'] = {'error': str(e)}

    try:
        results['network']['redirects'] = trace_redirects(full_url)
    except Exception as e:
        results['network']['redirects'] = {'error': str(e)}

    try:
        results['network']['subdomains'] = discover_subdomains(domain)
    except Exception as e:
        results['network']['subdomains'] = {'error': str(e)}

    try:
        results['network']['waf'] = detect_waf_cdn(full_url, domain)
    except Exception as e:
        results['network']['waf'] = {'error': str(e)}

    # ── Vulnerability Assessment ──
    try:
        results['vulnerability']['shodan'] = shodan_lookup(domain)
    except Exception as e:
        results['vulnerability']['shodan'] = {'error': str(e)}

    try:
        results['vulnerability']['ip_reputation'] = check_ip_reputation(domain)
    except Exception as e:
        results['vulnerability']['ip_reputation'] = {'error': str(e)}

    try:
        results['vulnerability']['ip_geolocation'] = get_ip_geolocation(domain)
    except Exception as e:
        results['vulnerability']['ip_geolocation'] = {'error': str(e)}

    # Calculate overall risk score
    results['risk_score'] = calculate_risk_score(results)

    # Generate threat model
    results['threat_model'] = generate_threat_model(results)

    return results


# ─── Helpers ──────────────────────────────────────────────────────────────────

def extract_domain(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    domain = domain.replace('www.', '')
    return domain if domain else None


def ensure_url(target):
    if not target.startswith(('http://', 'https://')):
        return 'https://' + target
    return target


# ─── Phishing Detection ──────────────────────────────────────────────────────

def check_safe_browsing(url):
    if not SAFE_BROWSING_API_KEY:
        return {'status': 'Skipped', 'reason': 'API key not configured'}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "cybermind-scanner", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"{endpoint}?key={SAFE_BROWSING_API_KEY}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if "matches" in data:
            threats = [match["threatType"] for match in data["matches"]]
            return {'status': 'Malicious', 'threats': threats, 'severity': 'critical'}
        return {'status': 'Safe', 'severity': 'safe'}

    except Exception as e:
        return {'status': 'Error', 'error': str(e)}


def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = (datetime.now() - creation_date).days if creation_date else None

        return {
            'creation_date': str(creation_date) if creation_date else 'Unknown',
            'expiration_date': str(expiration_date) if expiration_date else 'Unknown',
            'age_days': age_days,
            'registrar': w.registrar or 'Unknown',
            'name_servers': w.name_servers[:4] if w.name_servers else [],
            'is_new': age_days is not None and age_days < 90,
            'is_suspicious': age_days is not None and age_days < 30,
            'severity': 'high' if (age_days and age_days < 30) else 'medium' if (age_days and age_days < 90) else 'safe'
        }
    except Exception as e:
        return {'error': str(e), 'severity': 'unknown'}


# ─── Network Analysis ────────────────────────────────────────────────────────

def dns_lookup(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    resolver.timeout = 5
    resolver.lifetime = 5

    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == 'MX':
                records[rtype] = [str(r.exchange) for r in answers]
            else:
                records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    has_spf = any('spf' in txt.lower() for txt in records.get('TXT', []))
    has_dmarc = False
    try:
        resolver.resolve(f'_dmarc.{domain}', 'TXT')
        has_dmarc = True
    except Exception:
        pass

    return {
        'records': records,
        'has_spf': has_spf,
        'has_dmarc': has_dmarc,
        'ip_address': records.get('A', ['Unknown'])[0] if records.get('A') else 'Unknown',
        'severity': 'medium' if not has_spf or not has_dmarc else 'safe'
    }


def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.now()).days

        severity = 'safe'
        if days_remaining < 0:
            severity = 'critical'
        elif days_remaining < 30:
            severity = 'high'
        elif days_remaining < 90:
            severity = 'medium'

        return {
            'issued_to': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'valid_from': str(not_before),
            'valid_to': str(not_after),
            'days_remaining': days_remaining,
            'tls_version': tls_version,
            'cipher': cipher[0] if cipher else 'Unknown',
            'key_bits': cipher[2] if cipher and len(cipher) > 2 else 'Unknown',
            'is_valid': days_remaining > 0,
            'is_expired': days_remaining < 0,
            'severity': severity
        }
    except Exception as e:
        return {'error': str(e), 'severity': 'high'}


def check_security_headers(url):
    try:
        response = requests.get(url, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "CyberMind-Scanner/2.0"})
        headers = dict(response.headers)

        required_headers = {
            'Content-Security-Policy': 'Prevents XSS and code injection',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing',
            'X-XSS-Protection': 'Legacy XSS protection',
            'Referrer-Policy': 'Controls referrer information leakage',
            'Permissions-Policy': 'Controls browser feature access'
        }

        present = []
        missing = []
        for header, desc in required_headers.items():
            if header in headers:
                present.append({'header': header, 'value': headers[header][:100], 'description': desc})
            else:
                missing.append({'header': header, 'description': desc})

        score = len(present) / len(required_headers) * 100

        return {
            'present': present,
            'missing': missing,
            'score': round(score),
            'server': headers.get('Server', 'Unknown'),
            'status_code': response.status_code,
            'final_url': response.url,
            'severity': 'safe' if score >= 70 else 'medium' if score >= 40 else 'high'
        }
    except Exception as e:
        return {'error': str(e), 'severity': 'unknown'}


def basic_port_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {'error': f'Could not resolve {domain}', 'severity': 'unknown'}

    common_ports = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
    }

    open_ports = []
    risky_ports = {21, 23, 445, 3306, 3389, 5432}
    socket.setdefaulttimeout(1)

    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': service,
                    'risk': 'high' if port in risky_ports else 'low'
                })
            sock.close()
        except Exception:
            pass

    risky_open = [p for p in open_ports if p['risk'] == 'high']
    severity = 'high' if risky_open else 'safe' if len(open_ports) <= 3 else 'medium'

    return {
        'ip': ip,
        'open_ports': open_ports,
        'total_open': len(open_ports),
        'risky_ports': len(risky_open),
        'severity': severity
    }


# ─── Vulnerability Assessment ────────────────────────────────────────────────

def shodan_lookup(domain):
    if not SHODAN_API_KEY:
        return {'status': 'Skipped', 'reason': 'API key not configured', 'severity': 'unknown'}

    try:
        ip = socket.gethostbyname(domain)
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        vulns = host.get('vulns', [])
        services = []
        for item in host.get('data', []):
            services.append({
                'port': item['port'],
                'transport': item.get('transport', 'tcp'),
                'product': item.get('product', 'Unknown'),
                'version': item.get('version', '')
            })

        return {
            'ip': ip,
            'org': host.get('org', 'Unknown'),
            'isp': host.get('isp', 'Unknown'),
            'os': host.get('os', 'Unknown'),
            'ports': host.get('ports', []),
            'vulns': vulns[:20],
            'vuln_count': len(vulns),
            'services': services[:15],
            'country': host.get('country_name', 'Unknown'),
            'city': host.get('city', 'Unknown'),
            'last_update': host.get('last_update', 'Unknown'),
            'severity': 'critical' if len(vulns) > 5 else 'high' if len(vulns) > 0 else 'safe'
        }
    except shodan.APIError as e:
        return {'error': str(e), 'severity': 'unknown'}
    except Exception as e:
        return {'error': str(e), 'severity': 'unknown'}


def check_ip_reputation(domain):
    if not ABUSEIPDB_API_KEY:
        return {'status': 'Skipped', 'reason': 'API key not configured', 'severity': 'unknown'}

    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            timeout=10
        )
        data = response.json().get('data', {})

        abuse_score = data.get('abuseConfidenceScore', 0)
        return {
            'ip': ip,
            'abuse_score': abuse_score,
            'total_reports': data.get('totalReports', 0),
            'country': data.get('countryCode', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'domain': data.get('domain', 'Unknown'),
            'is_whitelisted': data.get('isWhitelisted', False),
            'last_reported': data.get('lastReportedAt', 'Never'),
            'severity': 'critical' if abuse_score > 75 else 'high' if abuse_score > 25 else 'safe'
        }
    except Exception as e:
        return {'error': str(e), 'severity': 'unknown'}


def get_ip_geolocation(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()

        if data.get('status') == 'success':
            return {
                'ip': ip,
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', ''),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'severity': 'safe'
            }
        return {'error': 'Geolocation lookup failed', 'severity': 'unknown'}
    except Exception as e:
        return {'error': str(e), 'severity': 'unknown'}


# ─── Risk Score Calculation ───────────────────────────────────────────────────

def calculate_risk_score(results):
    score = 0
    checks = 0
    severity_map = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'safe': 0, 'unknown': 30}

    def extract_severities(obj):
        nonlocal score, checks
        if isinstance(obj, dict):
            if 'severity' in obj and obj['severity'] in severity_map:
                score += severity_map[obj['severity']]
                checks += 1
            for v in obj.values():
                extract_severities(v)
        elif isinstance(obj, list):
            for item in obj:
                extract_severities(item)

    extract_severities(results)
    overall = round(score / checks) if checks > 0 else 0

    if overall >= 75:
        grade, label = 'F', 'Critical Risk'
    elif overall >= 50:
        grade, label = 'D', 'High Risk'
    elif overall >= 30:
        grade, label = 'C', 'Medium Risk'
    elif overall >= 15:
        grade, label = 'B', 'Low Risk'
    else:
        grade, label = 'A', 'Secure'

    return {'score': overall, 'grade': grade, 'label': label}


# ─── Deep Network Recon ──────────────────────────────────────────────────────

def detect_technology(url):
    """Detect server technology, frameworks, and CMS from HTTP response headers and HTML."""
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
        headers = resp.headers
        tech = []
        meta = {}

        # Server
        server = headers.get('Server', '')
        if server:
            tech.append({'name': server, 'category': 'Server'})
            meta['server'] = server

        # X-Powered-By
        powered = headers.get('X-Powered-By', '')
        if powered:
            tech.append({'name': powered, 'category': 'Framework'})
            meta['framework'] = powered

        # X-AspNet-Version
        aspnet = headers.get('X-AspNet-Version', '')
        if aspnet:
            tech.append({'name': f'ASP.NET {aspnet}', 'category': 'Framework'})

        # PHP via headers or cookies
        if 'PHPSESSID' in headers.get('Set-Cookie', ''):
            tech.append({'name': 'PHP', 'category': 'Language'})

        # Detect from HTML
        html = resp.text[:5000].lower()
        cms_signals = {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'shopify': 'Shopify',
            'wix.com': 'Wix',
            'squarespace': 'Squarespace',
            'next/static': 'Next.js',
            '__nuxt': 'Nuxt.js',
            'react': 'React',
            'angular': 'Angular',
            'vue.js': 'Vue.js',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
        }
        detected_cms = set()
        for signal, name in cms_signals.items():
            if signal in html and name not in detected_cms:
                detected_cms.add(name)
                tech.append({'name': name, 'category': 'CMS/Framework'})

        # Content-Type
        ct = headers.get('Content-Type', '')
        if ct:
            meta['content_type'] = ct.split(';')[0].strip()

        # HTTP version
        meta['http_version'] = f'HTTP/{resp.raw.version / 10:.1f}' if hasattr(resp.raw, 'version') and resp.raw.version else 'Unknown'
        meta['response_time'] = f'{resp.elapsed.total_seconds():.2f}s'
        meta['status_code'] = resp.status_code

        severity = 'safe'
        # Leak detection
        if server or powered or aspnet:
            severity = 'medium'
            meta['info_leak'] = True

        return {'technologies': tech, 'meta': meta, 'severity': severity, 'count': len(tech)}
    except Exception as e:
        return {'technologies': [], 'meta': {}, 'error': str(e), 'severity': 'unknown'}


def audit_cookies(url):
    """Audit cookies for security flags: Secure, HttpOnly, SameSite."""
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
        cookies = []
        issues = 0
        set_cookies = resp.headers.get('Set-Cookie', '')

        # Parse from response cookies jar
        for cookie in resp.cookies:
            c = {
                'name': cookie.name,
                'domain': cookie.domain or 'N/A',
                'path': cookie.path or '/',
                'secure': cookie.secure,
                'httponly': 'httponly' in str(cookie._rest).lower() if hasattr(cookie, '_rest') else False,
                'flags': []
            }
            if not cookie.secure:
                c['flags'].append('Missing Secure')
                issues += 1
            if not c['httponly']:
                c['flags'].append('Missing HttpOnly')
                issues += 1
            # Check SameSite from raw header
            c['samesite'] = 'Unknown'
            if 'samesite=strict' in set_cookies.lower():
                c['samesite'] = 'Strict'
            elif 'samesite=lax' in set_cookies.lower():
                c['samesite'] = 'Lax'
            elif 'samesite=none' in set_cookies.lower():
                c['samesite'] = 'None'
                if not cookie.secure:
                    c['flags'].append('SameSite=None without Secure')
                    issues += 1
            else:
                c['flags'].append('Missing SameSite')
                issues += 1
            cookies.append(c)

        severity = 'safe' if issues == 0 else ('high' if issues > 3 else 'medium')
        return {
            'cookies': cookies,
            'total': len(cookies),
            'issues': issues,
            'severity': severity if cookies else 'safe'
        }
    except Exception as e:
        return {'cookies': [], 'total': 0, 'issues': 0, 'error': str(e), 'severity': 'unknown'}


def trace_redirects(url):
    """Follow the full redirect chain and log each hop."""
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        chain = []
        if resp.history:
            for r in resp.history:
                chain.append({
                    'status': r.status_code,
                    'url': r.url,
                    'reason': r.reason
                })
        chain.append({
            'status': resp.status_code,
            'url': resp.url,
            'reason': resp.reason
        })
        # Check for protocol upgrade (HTTP -> HTTPS)
        has_https_upgrade = any(
            'https://' in c['url'] for c in chain
        ) and chain[0]['url'].startswith('http://')

        severity = 'safe'
        if len(chain) > 4:
            severity = 'medium'
        if not has_https_upgrade and chain[0]['url'].startswith('http://'):
            severity = 'medium'

        return {
            'chain': chain,
            'hops': len(chain) - 1,
            'final_url': resp.url,
            'https_upgrade': has_https_upgrade,
            'severity': severity
        }
    except Exception as e:
        return {'chain': [], 'hops': 0, 'error': str(e), 'severity': 'unknown'}


def discover_subdomains(domain):
    """Discover subdomains via Certificate Transparency logs (crt.sh)."""
    try:
        resp = requests.get(
            f'https://crt.sh/?q=%.{domain}&output=json',
            timeout=10,
            headers={'User-Agent': 'CyberSentry/2.0'}
        )
        if resp.status_code != 200:
            return {'subdomains': [], 'count': 0, 'reason': 'crt.sh unavailable', 'severity': 'unknown'}

        data = resp.json()
        # Extract unique subdomains
        subs = set()
        for entry in data:
            name = entry.get('name_value', '')
            for n in name.split('\n'):
                n = n.strip().lower()
                if n and '*' not in n and n != domain:
                    subs.add(n)

        subdomains = sorted(subs)[:25]  # Limit to 25
        severity = 'safe' if len(subdomains) < 10 else 'medium'

        return {
            'subdomains': subdomains,
            'count': len(subdomains),
            'total_certs': len(data),
            'severity': severity
        }
    except Exception as e:
        return {'subdomains': [], 'count': 0, 'error': str(e), 'severity': 'unknown'}


def detect_waf_cdn(url, domain):
    """Detect WAF/CDN presence from headers and DNS."""
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
        headers = resp.headers
        detected = []

        # Header-based detection
        waf_signatures = {
            'cf-ray': ('Cloudflare', 'CDN/WAF'),
            'cf-cache-status': ('Cloudflare', 'CDN'),
            'x-sucuri-id': ('Sucuri', 'WAF'),
            'x-sucuri-cache': ('Sucuri', 'WAF'),
            'x-akamai-transformed': ('Akamai', 'CDN'),
            'x-cdn': ('Generic CDN', 'CDN'),
            'x-amz-cf-id': ('AWS CloudFront', 'CDN'),
            'x-amz-cf-pop': ('AWS CloudFront', 'CDN'),
            'x-azure-ref': ('Azure CDN', 'CDN'),
            'x-ms-ref': ('Azure Front Door', 'CDN/WAF'),
            'x-fastly-request-id': ('Fastly', 'CDN'),
            'x-vercel-id': ('Vercel', 'CDN'),
            'x-netlify-request-id': ('Netlify', 'CDN'),
            'x-fw-hash': ('Imperva/Incapsula', 'WAF'),
        }

        seen = set()
        for header_name, (product, category) in waf_signatures.items():
            if header_name in {k.lower(): k for k in headers}:
                if product not in seen:
                    seen.add(product)
                    detected.append({
                        'name': product,
                        'type': category,
                        'evidence': f'Header: {header_name}'
                    })

        # Check for common WAF behaviors
        server = headers.get('Server', '').lower()
        if 'cloudflare' in server:
            if 'Cloudflare' not in seen:
                detected.append({'name': 'Cloudflare', 'type': 'CDN/WAF', 'evidence': 'Server header'})
        elif 'awselb' in server:
            if 'AWS ELB' not in seen:
                detected.append({'name': 'AWS ELB', 'type': 'Load Balancer', 'evidence': 'Server header'})
        elif 'akamaighost' in server:
            if 'Akamai' not in seen:
                detected.append({'name': 'Akamai', 'type': 'CDN', 'evidence': 'Server header'})

        # DNS-based CDN detection
        import socket
        try:
            cname_ips = socket.getaddrinfo(domain, None)
            ip = cname_ips[0][4][0] if cname_ips else ''
        except:
            ip = ''

        has_protection = len(detected) > 0
        severity = 'safe' if has_protection else 'medium'

        return {
            'detected': detected,
            'count': len(detected),
            'has_protection': has_protection,
            'severity': severity
        }
    except Exception as e:
        return {'detected': [], 'count': 0, 'error': str(e), 'severity': 'unknown'}


# ─── Threat Model Generator ──────────────────────────────────────────────────

def generate_threat_model(results):
    """
    Generates a STRIDE-based threat model from scan results.
    Analyzes attack surface, identifies threats, and recommends mitigations.
    """
    threats = []
    attack_surface = []
    mitigations = []

    net = results.get('network', {})
    vul = results.get('vulnerability', {})
    ph = results.get('phishing', {})
    risk = results.get('risk_score', {})

    # ── Analyze SSL/TLS ──
    ssl_data = net.get('ssl', {})
    if ssl_data.get('error'):
        threats.append({
            'category': 'Spoofing',
            'threat': 'Missing or invalid SSL certificate',
            'description': 'Without valid TLS, attackers can intercept traffic via man-in-the-middle attacks.',
            'likelihood': 'High',
            'impact': 'Critical',
            'stride': 'S'
        })
        attack_surface.append({'asset': 'TLS Endpoint', 'exposure': 'critical', 'detail': 'No valid certificate detected'})
        mitigations.append({'priority': 'critical', 'action': 'Install a valid SSL/TLS certificate', 'category': 'Encryption'})
    elif ssl_data.get('days_remaining', 999) < 30:
        threats.append({
            'category': 'Spoofing',
            'threat': 'SSL certificate expiring soon',
            'description': f'Certificate expires in {ssl_data.get("days_remaining")} days. Expiry causes browser warnings and trust loss.',
            'likelihood': 'Medium',
            'impact': 'High',
            'stride': 'S'
        })
        mitigations.append({'priority': 'high', 'action': 'Renew SSL certificate before expiry', 'category': 'Encryption'})
    if ssl_data.get('tls_version') and 'TLSv1.3' not in ssl_data.get('tls_version', ''):
        threats.append({
            'category': 'Tampering',
            'threat': 'Outdated TLS version in use',
            'description': f'Using {ssl_data.get("tls_version")}. Older TLS versions have known vulnerabilities.',
            'likelihood': 'Medium',
            'impact': 'Medium',
            'stride': 'T'
        })
        mitigations.append({'priority': 'medium', 'action': 'Upgrade to TLS 1.3 for best security', 'category': 'Encryption'})

    # ── Analyze Security Headers ──
    headers = net.get('headers', {})
    missing_headers = headers.get('missing', [])
    if missing_headers:
        critical_missing = [h['header'] for h in missing_headers if h['header'] in
                           ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options']]
        if critical_missing:
            threats.append({
                'category': 'Tampering',
                'threat': 'Missing critical security headers',
                'description': f'Headers missing: {", ".join(critical_missing)}. This enables XSS, clickjacking, and downgrade attacks.',
                'likelihood': 'High',
                'impact': 'High',
                'stride': 'T'
            })
            attack_surface.append({'asset': 'HTTP Headers', 'exposure': 'high', 'detail': f'{len(critical_missing)} critical headers missing'})
            for h in critical_missing:
                mitigations.append({'priority': 'high', 'action': f'Implement {h} header', 'category': 'Headers'})

        if any(h['header'] == 'Content-Security-Policy' for h in missing_headers):
            threats.append({
                'category': 'Elevation of Privilege',
                'threat': 'No Content Security Policy',
                'description': 'Without CSP, the site is vulnerable to XSS and code injection attacks.',
                'likelihood': 'High',
                'impact': 'Critical',
                'stride': 'E'
            })

    # ── Analyze Open Ports ──
    ports_data = net.get('ports', {})
    risky_ports = ports_data.get('risky_ports', 0)
    open_ports = ports_data.get('open_ports', [])
    if risky_ports > 0:
        risky_services = [f"{p['port']}/{p['service']}" for p in open_ports if p.get('risk') == 'high']
        threats.append({
            'category': 'Information Disclosure',
            'threat': f'{risky_ports} risky port(s) exposed',
            'description': f'Dangerous services exposed: {", ".join(risky_services)}. These are common attack entry points.',
            'likelihood': 'High',
            'impact': 'Critical',
            'stride': 'I'
        })
        attack_surface.append({'asset': 'Network Ports', 'exposure': 'critical', 'detail': f'{risky_ports} high-risk ports open'})
        mitigations.append({'priority': 'critical', 'action': 'Close or firewall risky ports (FTP, Telnet, SMB, RDP, DB)', 'category': 'Network'})

    if len(open_ports) > 5:
        threats.append({
            'category': 'Information Disclosure',
            'threat': 'Large attack surface from open ports',
            'description': f'{len(open_ports)} open ports detected. Each is a potential entry point for attackers.',
            'likelihood': 'Medium',
            'impact': 'Medium',
            'stride': 'I'
        })
        attack_surface.append({'asset': 'Network Ports', 'exposure': 'medium', 'detail': f'{len(open_ports)} total ports open'})

    # ── Analyze DNS Security ──
    dns_data = net.get('dns', {})
    if dns_data and not dns_data.get('error'):
        if not dns_data.get('has_spf'):
            threats.append({
                'category': 'Spoofing',
                'threat': 'Missing SPF record',
                'description': 'Without SPF, attackers can send emails pretending to be from this domain (email spoofing).',
                'likelihood': 'High',
                'impact': 'High',
                'stride': 'S'
            })
            mitigations.append({'priority': 'high', 'action': 'Add SPF DNS record to prevent email spoofing', 'category': 'DNS'})
        if not dns_data.get('has_dmarc'):
            threats.append({
                'category': 'Spoofing',
                'threat': 'Missing DMARC record',
                'description': 'Without DMARC, there is no policy for handling spoofed emails from this domain.',
                'likelihood': 'Medium',
                'impact': 'High',
                'stride': 'S'
            })
            mitigations.append({'priority': 'high', 'action': 'Implement DMARC policy for email authentication', 'category': 'DNS'})

    # ── Analyze Domain Age ──
    domain_info = ph.get('domain_info', {})
    if domain_info.get('is_suspicious'):
        threats.append({
            'category': 'Repudiation',
            'threat': 'Suspiciously new domain',
            'description': f'Domain registered only {domain_info.get("age_days")} days ago. New domains are frequently used for phishing.',
            'likelihood': 'Medium',
            'impact': 'High',
            'stride': 'R'
        })
        attack_surface.append({'asset': 'Domain', 'exposure': 'high', 'detail': 'Domain age < 30 days'})

    # ── Analyze Shodan / CVEs ──
    shodan_data = vul.get('shodan', {})
    vuln_count = shodan_data.get('vuln_count', 0)
    if vuln_count > 0:
        threats.append({
            'category': 'Elevation of Privilege',
            'threat': f'{vuln_count} known CVE(s) detected',
            'description': 'Known vulnerabilities can be exploited for remote code execution, privilege escalation, or denial of service.',
            'likelihood': 'High',
            'impact': 'Critical',
            'stride': 'E'
        })
        attack_surface.append({'asset': 'Software Stack', 'exposure': 'critical', 'detail': f'{vuln_count} CVEs from Shodan'})
        mitigations.append({'priority': 'critical', 'action': 'Patch all known CVEs immediately', 'category': 'Patching'})

    # ── Analyze IP Reputation ──
    ip_rep = vul.get('ip_reputation', {})
    abuse_score = ip_rep.get('abuse_score', 0)
    if abuse_score > 50:
        threats.append({
            'category': 'Denial of Service',
            'threat': 'Poor IP reputation',
            'description': f'Abuse score: {abuse_score}/100. High abuse scores indicate the IP is associated with malicious activity.',
            'likelihood': 'Medium',
            'impact': 'High',
            'stride': 'D'
        })
        attack_surface.append({'asset': 'IP Address', 'exposure': 'high', 'detail': f'Abuse score: {abuse_score}/100'})

    # ── Safe Browsing ──
    sb = ph.get('safe_browsing', {})
    if sb.get('status') == 'Malicious':
        threats.append({
            'category': 'Spoofing',
            'threat': 'Flagged as malicious by Google',
            'description': f'Threat types: {", ".join(sb.get("threats", []))}. This domain is actively dangerous.',
            'likelihood': 'Critical',
            'impact': 'Critical',
            'stride': 'S'
        })
        attack_surface.append({'asset': 'Web Application', 'exposure': 'critical', 'detail': 'Google Safe Browsing: MALICIOUS'})
    if not attack_surface:
        attack_surface.append({'asset': 'Overall', 'exposure': 'low', 'detail': 'No significant exposure detected'})
    if not mitigations:
        mitigations.append({'priority': 'low', 'action': 'Continue monitoring — no critical issues found', 'category': 'Monitoring'})
    stride_counts = {'S': 0, 'T': 0, 'R': 0, 'I': 0, 'D': 0, 'E': 0}
    for t in threats:
        s = t.get('stride', '')
        if s in stride_counts:
            stride_counts[s] += 1

    stride_labels = {
        'S': 'Spoofing', 'T': 'Tampering', 'R': 'Repudiation',
        'I': 'Info Disclosure', 'D': 'Denial of Service', 'E': 'Elevation of Privilege'
    }

    stride_summary = [{'code': k, 'name': v, 'count': stride_counts[k]} for k, v in stride_labels.items()]
    critical_count = sum(1 for t in threats if t.get('impact') == 'Critical')
    high_count = sum(1 for t in threats if t.get('impact') == 'High')
    if critical_count >= 2:
        overall_level = 'CRITICAL'
    elif critical_count >= 1 or high_count >= 3:
        overall_level = 'HIGH'
    elif high_count >= 1:
        overall_level = 'MEDIUM'
    else:
        overall_level = 'LOW'
    return {
        'overall_level': overall_level,
        'total_threats': len(threats),
        'threats': threats,
        'attack_surface': attack_surface,
        'mitigations': mitigations,
        'stride_summary': stride_summary,
        'critical_count': critical_count,
        'high_count': high_count
    }
if __name__ == '__main__':
    uvicorn.run(
        "application:app",
        host=os.getenv('FLASK_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_PORT', '5000')),
        reload=os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    )