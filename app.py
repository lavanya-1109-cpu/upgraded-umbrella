from html.parser import HTMLParser
from urllib.parse import urljoin
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, Response, g, has_request_context
import re
import sys
import os
import uuid
import csv
import threading
import ipaddress
import io
import ssl
import time
import socket
import json
import sqlite3
import joblib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

DB_PATH = BASE_DIR / "scans.db"


# Add backend directory to system path so feature_extraction can be imported
sys.path.insert(0, str(BASE_DIR))
from feature_extraction import extract_features

# Initialize Flask app (automatically looks inside backend/templates and backend/static)
app = Flask(__name__)

# Load the trained machine learning model safely
model = None
if MODEL_PATH.exists():
    loaded_data = joblib.load(MODEL_PATH)
    # Handle cases where model was saved inside a dictionary
    if isinstance(loaded_data, dict):
        model = loaded_data.get('model', loaded_data.get('classifier', loaded_data.get('clf', list(loaded_data.values())[0])))
    else:
        model = loaded_data
    print("Model loaded successfully!")
else:
    print(f"Warning: Model not found at {MODEL_PATH}. Run train_model.py first.")


# ---------------------------------------------------------------------------
# NEW: scan history database (SQLite is built into Python, nothing to install)
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   url TEXT,
                   prediction TEXT,
                   confidence REAL,
                   reasons TEXT,
                   created_at TEXT,
                   visitor TEXT)"""
        )
        # older databases get the new column added automatically
        columns = [row['name'] for row in conn.execute("PRAGMA table_info(scans)")]
        if 'visitor' not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN visitor TEXT")


def save_scan(url, prediction, confidence, reasons):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scans (url, prediction, confidence, reasons, created_at, visitor) VALUES (?,?,?,?,?,?)",
                (url, prediction, confidence, json.dumps(reasons),
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 g.get('vid') if has_request_context() else None),
            )
    except Exception as e:
        # History is a bonus feature, so never let it break a scan
        print("Could not save scan:", e)


init_db()


# ---------------------------------------------------------------------------
# NEW: for a public website. Every browser gets its own private history (a random
# cookie), and each visitor is limited to 40 scans a minute so nobody can overload it.
# ---------------------------------------------------------------------------
_rate = {}


@app.before_request
def visitor_and_limits():
    g.vid = request.cookies.get('pg_vid') or uuid.uuid4().hex
    g.new_vid = 'pg_vid' not in request.cookies
    if request.method == 'POST':
        ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '?').split(',')[0].strip()
        now = time.time()
        if len(_rate) > 2000:
            _rate.clear()
        recent = [t for t in _rate.get(ip, []) if now - t < 60]
        if len(recent) >= 40:
            return jsonify({'error': 'Too many requests. Please wait a minute and try again.'}), 429
        recent.append(now)
        _rate[ip] = recent


@app.after_request
def set_visitor_cookie(response):
    if g.get('new_vid'):
        response.set_cookie('pg_vid', g.vid, max_age=60 * 60 * 24 * 365, httponly=True, samesite='Lax')
    return response


# ---------------------------------------------------------------------------
# NEW: plain-English reasons shown under the result ("Why was this flagged?")
# ---------------------------------------------------------------------------
SUSPICIOUS_WORDS = ['login', 'signin', 'verify', 'update', 'secure', 'bank',
                    'account', 'confirm', 'password', 'wallet', 'suspend']
RISKY_TLDS = {'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'zip', 'work'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy'}


def explain_url(url):
    """Return (reasons, heuristics) describing risky-looking parts of the URL."""
    full = url if '://' in url else 'http://' + url
    parsed = urlparse(full)
    host = (parsed.hostname or '').lower()
    reasons = []

    has_ip = bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))
    has_at = '@' in parsed.netloc
    found_words = [w for w in SUSPICIOUS_WORDS if w in url.lower()]

    if parsed.scheme != 'https':
        reasons.append('Does not use HTTPS (connection is not encrypted)')
    if has_ip:
        reasons.append('Uses an IP address instead of a domain name')
    if has_at:
        reasons.append("Contains '@' - the real destination can be hidden")
    if len(url) > 75:
        reasons.append(f'Very long URL ({len(url)} characters)')
    if host.count('.') > 3:
        reasons.append('Too many subdomains')
    if host.count('-') >= 2:
        reasons.append('Several hyphens in the domain name')
    if host in SHORTENERS:
        reasons.append('URL shortener hides the real destination')
    if host.rsplit('.', 1)[-1] in RISKY_TLDS:
        reasons.append('Domain ending is often used for abuse')
    if found_words:
        reasons.append('Suspicious words in URL: ' + ', '.join(found_words))

    heuristics = {
        "has_ip": has_ip,
        "length": len(url),
        "has_at": has_at,
        "suspicious_keywords": bool(found_words),
    }
    return reasons, heuristics


# NEW: well-known safe sites. The ML model only reads the URL text, so it can wrongly flag
# short, clean addresses such as https://leetcode.com. Hybrid systems fix this with a trusted list.
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'wikipedia.org', 'github.com', 'leetcode.com',
    'stackoverflow.com', 'geeksforgeeks.org', 'w3schools.com', 'kaggle.com', 'medium.com',
    'microsoft.com', 'live.com', 'office.com', 'apple.com', 'amazon.com', 'amazon.in',
    'flipkart.com', 'linkedin.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com', 'reddit.com', 'netflix.com', 'paypal.com', 'zoom.us',
    'dropbox.com', 'adobe.com', 'mozilla.org', 'python.org', 'openai.com', 'anthropic.com',
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com', 'paytm.com',
    'phonepe.com', 'irctc.co.in', 'indiapost.gov.in', 'incometax.gov.in', 'uidai.gov.in', 'npci.org.in',
    'myntra.com', 'zomato.com', 'swiggy.com', 'jio.com', 'airtel.in',
    'claude.ai', 'hackerrank.com', 'codechef.com', 'coursera.org', 'udemy.com',
}


def trusted_domain_match(url):
    """Return the trusted domain this URL really belongs to, or None.
    'paypal.com.evil.com' does NOT match, because its real domain is evil.com."""
    parsed = urlparse(url if '://' in url else 'https://' + url)
    host = (parsed.hostname or '').lower()
    if not host or '@' in parsed.netloc or re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        return None
    registered = registered_domain(host)
    return registered if registered in TRUSTED_DOMAINS else None


def impersonated_brand(url):
    """Return (brand, real_domain) if the URL uses a famous brand name but belongs to another
    domain, e.g. 'paypal.com.evil.com' or 'paypal-secure-login.example.xyz'. Otherwise None."""
    parsed = urlparse(url if '://' in url else 'https://' + url)
    host = (parsed.hostname or '').lower()
    parts = host.split('.')
    if len(parts) < 2:
        return None
    registered = registered_domain(host)
    label = registered.split('.')[0]
    if registered in TRUSTED_DOMAINS:
        return None
    tokens = set(re.split(r'[^a-z0-9]+', host.translate(str.maketrans('01345', 'oleas'))))
    for domain in TRUSTED_DOMAINS:
        brand = domain.split('.')[0]
        if len(brand) >= 5 and brand != label and brand in tokens:
            return brand, registered
    return None


# NEW: which features the model leans on most ("Top factors" on the result card)
def get_top_factors(names, values, top_n=5):
    try:
        if not names or len(names) != len(values):
            return []
        if hasattr(model, "feature_importances_"):        # Random Forest, XGBoost, etc.
            weights = [float(w) for w in model.feature_importances_]
        elif hasattr(model, "coef_"):                      # Logistic Regression, linear SVM
            weights = [abs(float(c) * float(v)) for c, v in zip(model.coef_[0], values)]
        else:
            return []
        total = sum(weights) or 1.0
        ranked = sorted(zip(names, values, weights), key=lambda x: x[2], reverse=True)[:top_n]
        return [{
            "name": n.replace("_", " ").capitalize(),
            "value": int(v) if float(v).is_integer() else round(v, 2),
            "importance": round(w / total * 100, 1),
        } for n, v, w in ranked]
    except Exception as e:
        print("Could not compute top factors:", e)
        return []


# ---------------------------------------------------------------------------
# NEW: deep scan = domain age (WHOIS) + SSL certificate check. Needs internet.
# Install the WHOIS helper once with:  pip install python-whois
# ---------------------------------------------------------------------------
SECOND_LEVEL = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu'}


def registered_domain(host):
    parts = host.split('.')
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def _whois_age_days(domain):
    import whois  # pip install python-whois
    created = whois.whois(domain).creation_date
    if isinstance(created, list):
        created = created[0]
    if not created:
        return None
    return max(0, (datetime.now() - created.replace(tzinfo=None)).days)


def _ssl_status(host):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        days_left = int((ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400)
        if days_left < 0:
            return 'Certificate has expired', False
        return f'Valid certificate (expires in {days_left} days)', True
    except ssl.SSLCertVerificationError:
        return 'Certificate is invalid or does not match this domain', False
    except (OSError, ssl.SSLError):
        return 'Could not connect over HTTPS', None


def deep_scan(url):
    """Returns a dict with domain age and SSL status. Never raises."""
    host = (urlparse(url).hostname or '').lower()
    result = {'domain_age_days': None, 'ssl': 'Not checked', 'ssl_ok': None, 'notes': []}
    if not host or re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        result['notes'].append('Deep scan needs a domain name, not an IP address')
        return result
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            age = pool.submit(_whois_age_days, registered_domain(host)).result(timeout=8)
        result['domain_age_days'] = age
        if age is None:
            result['notes'].append('Domain registration date was not found')
    except FutureTimeout:
        result['notes'].append('Domain age lookup timed out')
    except ImportError:
        result['notes'].append('Domain age needs: pip install python-whois')
    except Exception:
        result['notes'].append('Domain age lookup failed (no internet, or the domain is not registered)')
    result['ssl'], result['ssl_ok'] = _ssl_status(host)
    return result


# ---------------------------------------------------------------------------
# One function that does a full scan. The single-URL page and the bulk upload both use it.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# NEW: page content check. Downloads the page's HTML as plain text (no scripts are run)
# and looks for phishing tricks. Needs:  pip install requests
# ---------------------------------------------------------------------------
def is_public_host(host):
    """Safety rule: never fetch localhost / private network addresses."""
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.passwords, self.forms, self.hidden_iframes, self.links = 0, [], 0, []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or '') for k, v in attrs}
        if tag == 'input' and a.get('type', '').lower() == 'password':
            self.passwords += 1
        elif tag == 'form':
            self.forms.append(a.get('action', ''))
        elif tag == 'iframe':
            style = a.get('style', '').replace(' ', '').lower()
            if 'display:none' in style or a.get('width') == '0' or a.get('height') == '0':
                self.hidden_iframes += 1
        elif tag == 'a':
            self._href, self._text = a.get('href', ''), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self._href is not None:
            self.links.append((self._href, ''.join(self._text).strip()))
            self._href = None


def page_check(url):
    """Returns (findings, notes). findings = list of (text, points, kind)."""
    try:
        import requests  # pip install requests
    except ImportError:
        return [], ['Page check needs: pip install requests']
    html, current = None, url
    try:
        for _ in range(4):  # follow at most 3 redirects, re-checking each address
            host = urlparse(current).hostname
            if urlparse(current).scheme not in ('http', 'https') or not host or not is_public_host(host):
                return [], ['Page check skipped: not a public website address']
            r = requests.get(current, timeout=6, allow_redirects=False, stream=True,
                             headers={'User-Agent': 'Mozilla/5.0 (PhishGuard student project)'})
            if 300 <= r.status_code < 400 and r.headers.get('Location'):
                current = urljoin(current, r.headers['Location'])
                continue
            html = next(r.iter_content(500000), b'').decode('utf-8', errors='ignore')
            break
    except Exception:
        return [], ['Page could not be downloaded (offline, blocked, or timed out)']
    if html is None:
        return [], ['Page redirected too many times']

    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    page_domain = registered_domain((urlparse(current).hostname or '').lower())
    findings = []
    if parser.passwords:
        findings.append((f'Page asks for a password ({parser.passwords} password field)', 10, 'password'))
    outside = [f for f in parser.forms if f.startswith(('http://', 'https://', '//'))
               and registered_domain((urlparse(f if '://' in f else 'https:' + f).hostname or '').lower()) != page_domain]
    if outside:
        findings.append(('A form on this page sends data to a different website', 25, 'form'))
    fake = 0
    for href, text in parser.links:
        if re.match(r'^(https?://)?[\w-]+(\.[\w-]+)+', text) and href.startswith('http'):
            shown = registered_domain((urlparse(text if '://' in text else 'http://' + text).hostname or '').lower())
            real = registered_domain((urlparse(href).hostname or '').lower())
            if shown and real and shown != real:
                fake += 1
    if fake:
        findings.append((f'{fake} link(s) show one address but lead to another', 10, 'links'))
    if parser.hidden_iframes:
        findings.append(('Hidden iframe found on the page', 10, 'iframe'))
    return findings, [] if findings else ['Page content looked normal']


# ---------------------------------------------------------------------------
# NEW: blacklist lookup. Three sources, all optional:
#   1. blacklist.txt   - your own list (one domain or URL per line, works offline)
#   2. OpenPhish feed  - free public list of live phishing URLs, downloaded automatically
#   3. Google Safe Browsing - only if you set a key:  $env:SAFE_BROWSING_KEY="your-key"
# ---------------------------------------------------------------------------
BLACKLIST_FILE = BASE_DIR / 'blacklist.txt'
FEED_CACHE = BASE_DIR / 'openphish_cache.txt'
_feed = {'urls': set(), 'loaded': 0.0, 'busy': False}


def norm_url(u):
    u = re.sub(r'^[a-z]+://', '', u.strip().lower())
    return re.sub(r'^www\.', '', u).rstrip('/')


def _load_feed_file():
    if FEED_CACHE.exists():
        lines = FEED_CACHE.read_text(encoding='utf-8', errors='ignore').splitlines()
        _feed['urls'] = {norm_url(l) for l in lines if l.strip()}
    _feed['loaded'] = time.time()


def _refresh_feed():
    try:
        import requests
        FEED_CACHE.write_text(requests.get('https://openphish.com/feed.txt', timeout=15).text, encoding='utf-8')
    except Exception:
        pass  # offline is fine, the old cache (if any) is used
    _load_feed_file()
    _feed['busy'] = False


def ensure_feed():
    """Loads the cached feed; refreshes it in the background if older than 6 hours."""
    if _feed['busy']:
        return
    age = time.time() - FEED_CACHE.stat().st_mtime if FEED_CACHE.exists() else 1e9
    if age > 6 * 3600 and time.time() - _feed['loaded'] > 600:
        _feed['busy'] = True
        threading.Thread(target=_refresh_feed, daemon=True).start()
    elif not _feed['urls'] and FEED_CACHE.exists() and not _feed['loaded']:
        _load_feed_file()


def safe_browsing_hit(url):
    key = os.environ.get('SAFE_BROWSING_KEY')
    if not key:
        return False
    try:
        import requests
        body = {'client': {'clientId': 'phishguard-student', 'clientVersion': '1.0'},
                'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
                               'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'],
                               'threatEntries': [{'url': url}]}}
        r = requests.post('https://safebrowsing.googleapis.com/v4/threatMatches:find',
                          params={'key': key}, json=body, timeout=5)
        return bool(r.json().get('matches'))
    except Exception:
        return False


def blacklist_hits(url, use_google=False):
    """Returns a list of blacklist names that contain this URL (empty list = clean)."""
    hits = []
    parsed = urlparse(url if '://' in url else 'https://' + url)
    host = (parsed.hostname or '').lower()
    target = norm_url(url)
    if BLACKLIST_FILE.exists():
        for line in BLACKLIST_FILE.read_text(encoding='utf-8', errors='ignore').splitlines():
            entry = line.strip().lower()
            if not entry or entry.startswith('#'):
                continue
            if '/' in entry:
                if norm_url(entry) == target:
                    hits.append('your blacklist.txt')
                    break
            elif host == entry or host.endswith('.' + entry):
                hits.append('your blacklist.txt')
                break
    ensure_feed()
    if target in _feed['urls']:
        hits.append('OpenPhish feed')
    if use_google and safe_browsing_hit(url):
        hits.append('Google Safe Browsing')
    return hits


def verdict_for(risk):
    return 'Safe' if risk < 35 else 'Suspicious' if risk < 65 else 'Phishing'


def phishing_probability(features_input, is_phishing):
    """ML probability (0-100) that the URL is phishing."""
    try:
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(features_input)[0]
            classes = list(model.classes_)
            for label in (0, -1, 'Phishing'):  # same meaning as the is_phishing line below
                if label in classes:
                    return float(probs[classes.index(label)]) * 100
    except Exception:
        pass
    return 100.0 if is_phishing else 0.0


# ---------------------------------------------------------------------------
# One function that does a full scan. The URL page, bulk upload and email scanner all use it.
# Result = a risk score from 0 to 100, turned into Safe / Suspicious / Phishing.
# ---------------------------------------------------------------------------
def analyze_url(url, deep=False, page=False):
    # If the user typed "github.com" with no http/https, assume https
    scan_url = url if '://' in url else 'https://' + url
    raw_features = extract_features(scan_url)

    if isinstance(raw_features, dict):
        feature_values = list(raw_features.values())
    elif hasattr(raw_features, "values"):
        feature_values = list(raw_features.values)
    else:
        feature_values = list(raw_features)
    features_list = [float(val) for val in feature_values]
    features_input = [features_list]

    prediction = model.predict(features_input)[0]
    print(f"DEBUG -> Raw Model Prediction for {url}: {prediction}")

    # --- PREDICTION MAPPING (unchanged from your version) ---
    is_phishing = (prediction == 0 or prediction == 'Phishing' or prediction == -1)
    risk = phishing_probability(features_input, is_phishing)

    reasons, heuristics = explain_url(scan_url)
    feature_names = list(raw_features.keys()) if isinstance(raw_features, dict) else []
    top_factors = get_top_factors(feature_names, features_list)
    source = 'ml_model'

    # Rule 1: a trusted domain overrides the ML model
    trusted = trusted_domain_match(scan_url)
    if trusted:
        reasons.insert(0, f'{trusted} is on the trusted-domain list')
        risk, source, top_factors = min(risk, 10), 'trusted_list', []

    # Rule 2: a famous brand name on someone else's domain
    fake = None if trusted else impersonated_brand(scan_url)
    if fake:
        reasons.insert(0, f"Uses the name '{fake[0]}' but the real domain is {fake[1]}")
        risk, source, top_factors = max(risk, 90), 'rule', []

    # Rule 3: known phishing blacklists
    hits = blacklist_hits(scan_url, use_google=deep)
    if hits:
        reasons.insert(0, 'Found on a phishing blacklist: ' + ', '.join(hits))
        risk, source, top_factors = max(risk, 95), 'blacklist', []

    # Rule 4 (deep scan): very new domain, bad SSL certificate
    deep_info = None
    if deep:
        deep_info = deep_scan(scan_url)
        age = deep_info['domain_age_days']
        if not trusted:
            if age is not None and age < 30:
                reasons.insert(0, f'Domain was registered only {age} days ago')
                risk, source = max(risk, 80), 'rule'
            elif age is not None and age < 180:
                reasons.append(f'Domain is fairly new ({age} days old)')
                risk += 15
            if deep_info['ssl_ok'] is False:
                reasons.append('SSL certificate problem: ' + deep_info['ssl'])
                risk += 15

    # Rule 5 (page content check): password boxes, forms sending data elsewhere, fake links
    page_notes = []
    if page:
        findings, page_notes = page_check(scan_url)
        if not trusted:
            kinds = {k for _, _, k in findings}
            for text, points, _ in findings:
                reasons.append('Page: ' + text)
                risk += points
            if 'password' in kinds and 'form' in kinds:
                risk, source = max(risk, 85), 'rule'

    risk = int(min(100, round(risk)))
    verdict = verdict_for(risk)
    return {
        'prediction': verdict,
        'risk': risk,
        'source': source,
        'heuristics': heuristics,
        'reasons': reasons,
        'top_factors': top_factors,
        'deep': deep_info,
        'page_notes': page_notes,
        'blacklist': hits,
        'url': url,
    }


# ---------------------------------------------------------------------------
# NEW: email scanner. Looks at the wording and scans every link inside the email.
# ---------------------------------------------------------------------------
LINK_RE = re.compile(r'(?:https?://|www\.)[^\s<>"\')\]]+', re.I)
URGENCY = ['urgent', 'immediately', 'act now', 'within 24 hours', 'suspended', 'will be closed',
           'unusual activity', 'verify your', 'confirm your', 'security alert', 'final notice',
           'account locked', 'expires today', 'limited time']
SENSITIVE = ['password', 'otp', 'one-time', 'card number', 'cvv', 'pin number', 'bank account',
             'login details', 'credentials', 'aadhaar', 'ssn']
GENERIC = ['dear customer', 'dear user', 'dear account holder', 'dear valued', 'dear sir/madam']


def analyze_email(text):
    low = text.lower()
    reasons, text_score = [], 0
    urgent = [w for w in URGENCY if w in low]
    sensitive = [w for w in SENSITIVE if w in low]
    generic = [w for w in GENERIC if w in low]
    if urgent:
        text_score += min(40, 12 * len(urgent))
        reasons.append('Urgent or threatening wording: ' + ', '.join(urgent[:4]))
    if sensitive:
        text_score += min(40, 18 * len(sensitive))
        reasons.append('Asks for sensitive information: ' + ', '.join(sensitive[:4]))
    if generic:
        text_score += 10
        reasons.append('Generic greeting instead of your name')

    links, seen = [], set()
    for raw in LINK_RE.findall(text):
        u = raw.rstrip('.,;:!?')
        if u not in seen and len(links) < 10:
            seen.add(u)
            r = analyze_url(u)
            links.append({'url': u, 'prediction': r['prediction'], 'risk': r['risk'],
                          'reason': r['reasons'][0] if r['reasons'] else ''})
    link_max = max([l['risk'] for l in links], default=0)
    if not links:
        reasons.append('No links found in this email')
    elif link_max >= 65:
        reasons.append('Contains a link that looks like phishing')
    elif link_max >= 35:
        reasons.append('Contains a suspicious-looking link')

    risk = max(link_max, min(100, text_score))
    if link_max >= 35 and text_score >= 30:
        risk += 10  # pressure wording plus a risky link is the classic phishing pattern
    risk = int(min(100, risk))
    return {'prediction': verdict_for(risk), 'risk': risk, 'reasons': reasons, 'links': links}


# ---------------------------------------------------------------------------
# NEW: SMS / WhatsApp scanner. Looks for common Indian scam patterns (fake KYC, parcel fee,
# lottery, bill-cut threats, fake jobs, APK installs) and scans every link in the message.
# ---------------------------------------------------------------------------
SCAM_THEMES = {
    'KYC or account update': ['kyc', 'update your pan', 'pan card update', 'update your account'],
    'bill disconnection threat': ['will be disconnected', 'disconnection', 'power cut tonight', 'bill is overdue', 'bill not updated'],
    'parcel or delivery fee': ['parcel', 'courier', 'delivery failed', 'could not be delivered', 'redelivery', 'customs fee', 'package on hold'],
    'prize or lottery': ['you have won', 'you won', 'lucky draw', 'lottery', 'congratulations', 'kbc', 'prize money', 'claim your prize', 'gift voucher'],
    'tax or bank refund': ['refund', 'income tax', 'cashback of', 'claim your refund'],
    'job or easy-money offer': ['work from home', 'part-time job', 'part time job', 'earn up to', 'earn rs', 'daily income', 'simple tasks', 'telegram'],
    'fake loan offer': ['instant loan', 'loan approved', 'pre-approved loan', 'loan without documents'],
    'SIM or card blocking': ['sim will be blocked', 'sim blocked', 'card will be blocked', 'debit card blocked', 'account will be blocked',
                             'account is blocked', 'account blocked', 'account has been blocked', 'account will be suspended', 'upi blocked'],
}
MSG_URGENCY = ['urgent', 'immediately', 'within 24 hours', 'expires today', 'expiring today', 'last chance', 'act now',
               'final notice', 'hurry', 'right now', 'before midnight', 'today only']
OFFICIAL_SITES = {  # brand name in the message -> its real website(s)
    'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com'], 'hdfc': ['hdfcbank.com'], 'icici': ['icicibank.com'],
    'axis bank': ['axisbank.com'], 'kotak': ['kotak.com'], 'paytm': ['paytm.com'], 'phonepe': ['phonepe.com'],
    'google pay': ['google.com', 'pay.google.com'], 'amazon': ['amazon.in', 'amazon.com'], 'flipkart': ['flipkart.com'],
    'india post': ['indiapost.gov.in'], 'income tax': ['incometax.gov.in'], 'aadhaar': ['uidai.gov.in'],
    'irctc': ['irctc.co.in'], 'jio': ['jio.com'], 'airtel': ['airtel.in'],
}
SHORT_HOSTS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy', 'shorturl.at'}
NEGATED_RE = re.compile(r"(do not|don't|dont|never)\s+(share|send|give|tell|disclose|provide)[^.\n]*")
ASK_VERB_RE = re.compile(r"\b(share|send|tell|give|provide|reply|forward)\b([^.\n]{0,60})")
SENSITIVE_RE = re.compile(r"\b(otp|pin|cvv|password|passcode|aadhaar|aadhar|pan|card number|account number)\b")
APK_RE = re.compile(r"\.apk\b|install (?:the |this |our )?app|download (?:the |this |our )?app|anydesk|teamviewer|quicksupport")
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?\b[6-9]\d{9}\b")
CALL_RE = re.compile(r"\b(call|dial|whatsapp|contact)\b")
GREETING_RE = re.compile(r"dear\s+(valued\s+)?(\w+\s+){0,2}(customer|user|member|holder|sir/madam)")


def analyze_message(text):
    low = text.lower()
    reasons, score = [], 0

    urgent = [w for w in MSG_URGENCY if w in low]
    if urgent:
        score += min(36, 12 * len(urgent))
        reasons.append('Urgent or threatening wording: ' + ', '.join(urgent[:4]))

    asked = set()
    for m in ASK_VERB_RE.finditer(NEGATED_RE.sub('', low)):
        asked.update(SENSITIVE_RE.findall(m.group(2)))
    if asked:
        score += min(60, 30 * len(asked))
        reasons.append('Asks for sensitive information: ' + ', '.join(sorted(asked)[:4]))

    themes = [name for name, words in SCAM_THEMES.items() if any(w in low for w in words)]
    for name in themes[:3]:
        score += 20
        reasons.append('Common scam theme: ' + name)

    if APK_RE.search(low):
        score += 30
        reasons.append('Asks you to install an app or remote-access tool')
    if PHONE_RE.search(text) and CALL_RE.search(low):
        score += 10
        reasons.append('Asks you to call or contact a phone number')
    if GREETING_RE.search(low):
        score += 10
        reasons.append('Generic greeting instead of your name')

    links, seen, link_domains = [], set(), []
    for raw in LINK_RE.findall(text):
        u = raw.rstrip('.,;:!?')
        if u in seen or len(links) >= 10:
            continue
        seen.add(u)
        host = (urlparse(u if '://' in u else 'http://' + u).hostname or '').lower()
        link_domains.append(registered_domain(host))
        r = analyze_url(u)
        links.append({'url': u, 'prediction': r['prediction'], 'risk': r['risk'],
                      'reason': r['reasons'][0] if r['reasons'] else ''})
    if any(d in SHORT_HOSTS for d in link_domains):
        score += 20
        reasons.append('Uses a short link that hides the real address')
    for brand, sites in OFFICIAL_SITES.items():
        if re.search(r'\b' + re.escape(brand) + r'\b', low) and link_domains and not any(d in sites for d in link_domains):
            score += 35
            reasons.append(f"Mentions {brand.upper() if len(brand) <= 5 else brand.title()} but the link goes to {link_domains[0]}")
            break

    link_max = max([l['risk'] for l in links], default=0)
    if not links:
        reasons.append('No links found in this message')
    elif link_max >= 65:
        reasons.append('Contains a link that looks like phishing')
    elif link_max >= 35:
        reasons.append('Contains a suspicious-looking link')
    if score == 0 and link_max < 35:
        reasons.insert(0, 'No scam signs found in this message')

    risk = max(link_max, min(100, score))
    if link_max >= 35 and score >= 30:
        risk += 10
    risk = int(min(100, risk))
    return {'prediction': verdict_for(risk), 'risk': risk, 'reasons': reasons, 'links': links}


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided'}), 400

        if model is None:
            return jsonify({'error': 'Model not loaded on server'}), 500

        result = analyze_url(url, deep=bool(data.get('deep')), page=bool(data.get('page')))
        save_scan(url, result['prediction'], result['risk'], result['reasons'])
        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# NEW: check many URLs from an uploaded .csv or .txt file (one URL per line)
@app.route('/bulk', methods=['POST'])
def bulk():
    if model is None:
        return jsonify({'error': 'Model not loaded on server'}), 500
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'Choose a .csv or .txt file first.'}), 400

    text = file.read().decode('utf-8-sig', errors='ignore')
    urls = []
    for row in csv.reader(io.StringIO(text)):
        if row and row[0].strip() and row[0].strip().lower() != 'url':
            urls.append(row[0].strip())
    if not urls:
        return jsonify({'error': 'No URLs found in that file.'}), 400

    limit = 100
    results = []
    for u in urls[:limit]:
        try:
            r = analyze_url(u)
            save_scan(u, r['prediction'], r['risk'], r['reasons'])
            results.append({'url': u, 'prediction': r['prediction'], 'risk': r['risk'],
                            'reason': r['reasons'][0] if r['reasons'] else ''})
        except Exception as e:
            results.append({'url': u, 'prediction': 'Error', 'risk': None, 'reason': str(e)})
    return jsonify({'count': len(results), 'skipped': max(0, len(urls) - limit), 'results': results})


# NEW: scan the text of an email
@app.route('/email', methods=['POST'])
def email_scan():
    text = ((request.get_json() or {}).get('text') or '').strip()[:20000]
    if not text:
        return jsonify({'error': 'Paste the email text first.'}), 400
    if model is None:
        return jsonify({'error': 'Model not loaded on server'}), 500
    try:
        result = analyze_email(text)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    snippet = ' '.join(text.split())[:50]
    save_scan('Email: ' + snippet, result['prediction'], result['risk'], result['reasons'])
    return jsonify(result)


# NEW: scan an SMS or WhatsApp message
@app.route('/message', methods=['POST'])
def message_scan():
    text = ((request.get_json() or {}).get('text') or '').strip()[:5000]
    if not text:
        return jsonify({'error': 'Paste the message first.'}), 400
    if model is None:
        return jsonify({'error': 'Model not loaded on server'}), 500
    try:
        result = analyze_message(text)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    save_scan('Message: ' + ' '.join(text.split())[:50], result['prediction'], result['risk'], result['reasons'])
    return jsonify(result)


# NEW: download the whole scan history as a .csv file (opens in Excel)
@app.route('/export.csv')
def export_csv():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT created_at, url, prediction, confidence, reasons FROM scans WHERE visitor = ? ORDER BY id DESC", (g.vid,)
        ).fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['time', 'url', 'result', 'risk', 'reasons'])
    for r in rows:
        writer.writerow([r['created_at'], r['url'], r['prediction'],
                         '' if r['confidence'] is None else r['confidence'],
                         '; '.join(json.loads(r['reasons'] or '[]'))])
    return Response(buffer.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=scan_history.csv'})


# NEW: empty the history (used by the "Clear history" button)
@app.route('/clear', methods=['POST'])
def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM scans WHERE visitor = ?", (g.vid,))
    return jsonify({'ok': True})


# Last 20 scans for the "Recent scans" table
@app.route('/history')
def history():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT url, prediction, confidence, created_at FROM scans WHERE visitor = ? ORDER BY id DESC LIMIT 20", (g.vid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# Totals for the stats strip
@app.route('/stats')
def stats():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT prediction, COUNT(*) AS n FROM scans WHERE visitor = ? GROUP BY prediction", (g.vid,)
        ).fetchall()
    counts = {'Safe': 0, 'Suspicious': 0, 'Phishing': 0}
    for r in rows:
        counts[r['prediction']] = r['n']
    counts['total'] = counts['Safe'] + counts['Suspicious'] + counts['Phishing']
    return jsonify(counts)


# NEW: data for the charts dashboard (last 7 days + the most common warning signs)
REASON_KEYS = [
    ('Does not use HTTPS', 'no_https'), ('Uses an IP address', 'ip_address'), ("Contains '@'", 'at_symbol'),
    ('Very long URL', 'long_url'), ('Too many subdomains', 'subdomains'), ('Several hyphens', 'hyphens'),
    ('URL shortener', 'shortener'), ('Domain ending', 'risky_tld'), ('Suspicious words', 'suspicious_words'),
    ('Uses the name', 'brand'), ('Found on a phishing blacklist', 'blacklist'),
    ('Domain was registered only', 'new_domain'), ('Domain is fairly new', 'young_domain'),
    ('SSL certificate problem', 'ssl'), ('asks for a password', 'page_password'),
    ('sends data to a different website', 'page_form'), ('link(s) show one address', 'page_links'),
    ('Hidden iframe', 'page_iframe'), ('Urgent or threatening', 'urgent'),
    ('Asks for sensitive', 'sensitive'), ('Generic greeting', 'generic'),
    ('looks like phishing', 'bad_link'), ('suspicious-looking link', 'bad_link'),
    ('Common scam theme', 'scam_theme'), ('install an app', 'apk'), ('call or contact a phone number', 'call_number'),
    ('but the link goes to', 'brand_link'), ('short link', 'short_link'),
]


def reason_key(text):
    for needle, key in REASON_KEYS:
        if needle in text:
            return key
    return None


@app.route('/dashboard')
def dashboard():
    days = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    with get_db() as conn:
        rows = conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, prediction, COUNT(*) AS n FROM scans "
            "WHERE visitor = ? AND substr(created_at, 1, 10) >= ? GROUP BY 1, 2", (g.vid, days[0])
        ).fetchall()
        reason_rows = conn.execute(
            "SELECT reasons FROM scans WHERE visitor = ? AND prediction != 'Safe' ORDER BY id DESC LIMIT 300", (g.vid,)
        ).fetchall()
    per_day = {d: {'Safe': 0, 'Suspicious': 0, 'Phishing': 0} for d in days}
    for r in rows:
        if r['day'] in per_day and r['prediction'] in per_day[r['day']]:
            per_day[r['day']][r['prediction']] = r['n']
    counter = {}
    for r in reason_rows:
        for key in {reason_key(t) for t in json.loads(r['reasons'] or '[]')} - {None}:
            counter[key] = counter.get(key, 0) + 1
    top = sorted(counter.items(), key=lambda kv: -kv[1])[:5]
    return jsonify({'days': [dict(date=d, **per_day[d]) for d in days],
                    'top_reasons': [{'key': k, 'count': c} for k, c in top]})


if __name__ == '__main__':
    app.run(debug=True, port=5000)