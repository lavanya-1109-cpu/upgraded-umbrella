
from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update",
    "password", "bank", "signin", "confirm", "wallet"
]


def extract_features(url):
    url = str(url).strip()

    # Add a scheme for parsing if the URL has none
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Check whether the hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    url_lower = url.lower()

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "ampersand_count": url.count("&"),
        "digit_count": sum(char.isdigit() for char in url),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "has_ip_address": has_ip,
        "path_length": len(path),
        "percent_count": url.count("%"),
        "suspicious_word_count": sum(
            word in url_lower for word in SUSPICIOUS_WORDS
        ),
        "special_character_count": len(re.findall(r"[^a-zA-Z0-9]", url))
    }

    return features
