#!/usr/bin/env python3
"""
Network Feature Extractor using cloudscraper to bypass bot detection
Supports SSL, DNS, WHOIS, HTML, Security Headers, Cookies
"""

import cloudscraper
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import re
import time
import logging
import os
import ssl
import socket
import dns.asyncresolver
import dns.exception
import whois
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple
import argparse
import asyncio

# --- Configuration ---
CONCURRENCY_LIMIT = 20
REQUEST_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
WHOIS_TIMEOUT = 15
DNS_TIMEOUT = 5
DNS_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
SSL_TIMEOUT = 10
BATCH_SIZE = 20

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("network_features.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Feature Defaults ---
NETWORK_FEATURE_DEFAULTS = {
    "dns_a_presence": None, "dns_a_count": None,
    "dns_mx_presence": None, "dns_mx_count": None,
    "dns_txt_presence": None, "dns_txt_count": None,
    "dns_ns_presence": None, "dns_ns_count": None,
    "dns_spf_presence": None, "dns_spf_count": None,
    "dns_dkim_presence": None, "dns_dkim_count": None,
    "dns_dmarc_presence": None, "dns_dmarc_count": None,
    "has_ssl_certificate": None, "ssl_certificate_valid": None,
    "ssl_days_to_expiry": None, "ssl_is_expired": None,
    "ssl_is_self_signed": None, "ssl_has_chain_issues": None,
    "ssl_hostname_mismatch": None, "ssl_connection_error": None,
    "domain_age_days": None, "time_to_expiration": None,
    "redirect_count": None, "final_url_diff": None,
    "response_time": None, "content_length": None,
    "has_title": None, "title_length": None,
    "has_iframe": None, "num_iframes": None,
    "has_text_input": None, "has_password_input": None,
    "has_button": None, "has_image": None,
    "has_submit": None, "has_link": None,
    "num_links": None, "num_images": None,
    "num_scripts": None, "has_javascript": None,
    "has_favicon": None, "num_a_tags": None,
    "has_xss_protection": None, "has_csp": None,
    "has_hsts": None, "has_x_frame_options": None,
    "has_x_content_type_options": None,
    "has_referrer_policy": None, "has_feature_policy": None,
    "has_cookie": None, "has_http_only_cookie": None, "has_secure_cookie": None,
}

# --- Helpers ---
def ensure_url_scheme(url: str) -> str:
    if not isinstance(url, str): return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return f"http://{url}"
    return url

def get_registered_domain(url: str) -> Optional[str]:
    try:
        if not url or not isinstance(url, str): return None
        url = ensure_url_scheme(url.strip())
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0]
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", netloc): return netloc
        extracted = tldextract.extract(netloc)
        return f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else netloc
    except Exception as e:
        logger.warning(f"Domain extraction failed for {url}: {e}")
        return None

def get_hostname_from_url(url: str) -> Optional[str]:
    try:
        url = ensure_url_scheme(url.strip())
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname): return None
        return hostname or None
    except Exception as e:
        logger.warning(f"Hostname extraction failed for {url}: {e}")
        return None

def is_valid_domain(domain: str) -> bool:
    if not domain: return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain): return False
    if domain.lower() in ["localhost", "127.0.0.1"]: return False
    return 4 <= len(domain) <= 253

# --- SSL ---
def matches_hostname(cert_hostname: str, actual_hostname: str) -> bool:
    cert_hostname = cert_hostname.lower()
    actual_hostname = actual_hostname.lower()
    if cert_hostname == actual_hostname: return True
    if cert_hostname.startswith("*."):
        base = cert_hostname[2:]
        return actual_hostname.count(".") == base.count(".") + 1 and actual_hostname.endswith("." + base)
    return False

async def check_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    res = {
        "has_ssl_certificate": 0, "ssl_certificate_valid": 0, "ssl_days_to_expiry": -1,
        "ssl_is_expired": 0, "ssl_is_self_signed": 0, "ssl_has_chain_issues": 0,
        "ssl_hostname_mismatch": 0, "ssl_connection_error": 0,
    }
    if not hostname:
        res["ssl_connection_error"] = 1
        return res

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        r, w = await asyncio.wait_for(asyncio.open_connection(hostname, port, ssl=ctx), SSL_TIMEOUT)
        res.update({"has_ssl_certificate": 1, "ssl_certificate_valid": 1})
        cert = w.get_extra_info('peercert')
        if cert:
            await parse_ssl_certificate(cert, hostname, res)
        w.close()
        await w.wait_closed()
        return res
    except ssl.SSLCertVerificationError as e:
        res["ssl_certificate_valid"] = 0
        msg = str(e).lower()
        if 'hostname mismatch' in msg: res["ssl_hostname_mismatch"] = 1
        if 'expired' in msg: res["ssl_is_expired"] = 1
        if 'self-signed' in msg: res["ssl_is_self_signed"] = 1
        if 'verify failed' in msg: res["ssl_has_chain_issues"] = 1
    except (ConnectionRefusedError, OSError, socket.gaierror, asyncio.TimeoutError):
        res["ssl_connection_error"] = 1
    except Exception as e:
        logger.debug(f"SSL error: {e}")
        res["ssl_connection_error"] = 1
    return res

async def parse_ssl_certificate(cert: dict, host: str, res: dict):
    try:
        exp = cert.get('notAfter')
        if exp:
            dt = datetime.strptime(exp, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            days = (dt - datetime.now(timezone.utc)).days
            res["ssl_days_to_expiry"] = days
            if days < 0: res["ssl_is_expired"] = 1
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        if issuer.get('commonName') == subject.get('commonName'): res["ssl_is_self_signed"] = 1
        sans = [ext[1] for ext in cert.get('subjectAltName', []) if ext[0] == 'DNS']
        cn = subject.get('commonName', '')
        if not any(matches_hostname(n, host) for n in [cn] + sans) and not res["ssl_hostname_mismatch"]:
            res["ssl_hostname_mismatch"] = 1
    except Exception as e:
        logger.warning(f"Parse SSL error: {e}")

async def fetch_ssl_cert(url: str) -> Dict[str, Any]:
    host = get_hostname_from_url(url)
    return await check_ssl_certificate(host, 443) if host else {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("ssl_")}

# --- DNS ---
async def fetch_dns_records(domain: str) -> Dict[str, Any]:
    res = {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("dns_")}
    if not is_valid_domain(domain): return res

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT * 2
    resolver.nameservers = DNS_RESOLVERS

    for rdtype, (p, c) in {
        "A": ("dns_a_presence", "dns_a_count"),
        "MX": ("dns_mx_presence", "dns_mx_count"),
        "TXT": ("dns_txt_presence", "dns_txt_count"),
        "NS": ("dns_ns_presence", "dns_ns_count"),
    }.items():
        try:
            ans = await resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            res[p] = 1 if ans.rrset else 0
            res[c] = len(ans.rrset) if ans.rrset else 0
            if rdtype == "TXT": txt_records = ans
        except Exception:
            res[p] = 0
            res[c] = 0

    # SPF
    spf = 0
    if 'txt_records' in locals():
        for r in txt_records.rrset:
            if b"v=spf1" in b"".join(r.strings).lower(): spf += 1
    res["dns_spf_presence"] = 1 if spf > 0 else 0
    res["dns_spf_count"] = spf

    # DKIM
    try:
        ans = await resolver.resolve(f"default._domainkey.{domain}", "TXT", raise_on_no_answer=False)
        res["dns_dkim_presence"] = 1 if ans.rrset else 0
        res["dns_dkim_count"] = len(ans.rrset) if ans.rrset else 0
    except Exception:
        res["dns_dkim_presence"] = 0
        res["dns_dkim_count"] = 0

    # DMARC
    try:
        ans = await resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
        dmarc = sum(1 for r in ans.rrset if b"v=dmarc1" in b"".join(r.strings).lower()) if ans.rrset else 0
        res["dns_dmarc_presence"] = 1 if dmarc > 0 else 0
        res["dns_dmarc_count"] = dmarc
    except Exception:
        res["dns_dmarc_presence"] = 0
        res["dns_dmarc_count"] = 0

    return res

# --- WHOIS ---
def fetch_whois(domain: str) -> Tuple[Optional[int], Optional[int]]:
    age = expiry = None
    if not is_valid_domain(domain): return age, expiry
    try:
        w = whois.whois(domain)
        def get_date(d):
            if isinstance(d, list): d = [x for x in d if isinstance(x, datetime)]; return min(d) if d else None
            return d if isinstance(d, datetime) else None
        created = get_date(w.creation_date)
        expires = get_date(w.expiration_date)
        now = datetime.now(timezone.utc)
        if created and created <= now: age = (now - created).days
        if expires: expiry = (expires - now).days
    except Exception as e:
        logger.debug(f"WHOIS failed for {domain}: {e}")
    return age, expiry

async def fetch_whois_async(domain: str, executor: ThreadPoolExecutor) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    age, expiry = await loop.run_in_executor(executor, fetch_whois, domain)
    return {"domain_age_days": age, "time_to_expiration": expiry}

# --- HTML (cloudscraper) ---
def fetch_html_features_sync(url: str) -> Dict[str, Any]:
    res = {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("has_") or "num_" in k or k in ["response_time", "content_length", "redirect_count", "final_url_diff", "title_length"]}
    try:
        scraper = cloudscraper.create_scraper(browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False})
        start = time.time()
        resp = scraper.get(ensure_url_scheme(url), timeout=REQUEST_TIMEOUT, allow_redirects=True)
        res["response_time"] = time.time() - start
        res["redirect_count"] = len(resp.history)
        res["final_url_diff"] = 1 if resp.url.lower() != ensure_url_scheme(url).lower() else 0
        res["content_length"] = len(resp.content)

        # Headers
        h = {k.lower(): v for k, v in resp.headers.items()}
        for header, feat in {
            "x-xss-protection": "has_xss_protection",
            "content-security-policy": "has_csp",
            "strict-transport-security": "has_hsts",
            "x-frame-options": "has_x_frame_options",
            "x-content-type-options": "has_x_content_type_options",
            "referrer-policy": "has_referrer_policy",
            "feature-policy": "has_feature_policy"
        }.items():
            res[feat] = 1 if header in h else 0

        # Cookies
        if resp.cookies:
            res["has_cookie"] = 1
            for c in resp.cookies:
                if hasattr(c, 'httponly') and c.httponly: res["has_http_only_cookie"] = 1
                if c.secure: res["has_secure_cookie"] = 1

        # HTML
        soup = BeautifulSoup(resp.text, "lxml")
        title = soup.find("title")
        res["has_title"] = 1 if title and title.get_text(strip=True) else 0
        res["title_length"] = len(title.get_text(strip=True)) if title else 0

        res.update({
            "num_iframes": len(soup.find_all("iframe")),
            "has_iframe": 1 if soup.find("iframe") else 0,
            "num_scripts": len(soup.find_all("script")),
            "has_javascript": 1 if soup.find("script") else 0,
            "num_links": len(soup.find_all("a", href=True)),
            "has_link": 1 if soup.find("a", href=True) else 0,
            "num_a_tags": len(soup.find_all("a")),
            "num_images": len(soup.find_all("img")),
            "has_image": 1 if soup.find("img") else 0,
            "has_text_input": 1 if soup.find("input", type=lambda t: t and t.lower() in ["text", "search", "email"]) else 0,
            "has_password_input": 1 if soup.find("input", type="password") else 0,
            "has_submit": 1 if soup.find("input", type="submit") or soup.find("button", type="submit") else 0,
            "has_button": 1 if soup.find("button") else 0,
        })

        favicon_selectors = [
            {"rel": "icon"}, {"rel": "shortcut icon"},
            {"href": lambda x: x and "favicon" in x.lower()}
        ]
        res["has_favicon"] = 1 if any(soup.find("link", **sel) for sel in favicon_selectors) else 0

    except Exception as e:
        logger.warning(f"HTML fetch failed for {url}: {e}")
    return res

async def fetch_html_features(url: str, executor: ThreadPoolExecutor) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, fetch_html_features_sync, url)

# --- Processing ---
async def process_single_url(row, executor, semaphore):
    async with semaphore:
        url = str(row.get("url", "")).strip()
        features = NETWORK_FEATURE_DEFAULTS.copy()
        if not url or url.lower() in ["nan", "<na>"]:
            return {**row.to_dict(), **features}

        try:
            status_code = int(row.get("http_status", 0))
            if not (200 <= status_code <= 299):
                return {**row.to_dict(), **features}
        except (TypeError, ValueError):
            return {**row.to_dict(), **features}

        domain = get_registered_domain(url)
        tasks = []
        if domain and is_valid_domain(domain):
            tasks.append(fetch_dns_records(domain))
            tasks.append(fetch_whois_async(domain, executor))
        tasks.append(fetch_ssl_cert(url))
        tasks.append(fetch_html_features(url, executor))

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception): continue
                features.update(r)
        except Exception as e:
            logger.error(f"Processing failed for {url}: {e}")

        return {**row.to_dict(), **features}

# --- I/O ---
def get_processed_urls(output_csv: str) -> set:
    if not os.path.exists(output_csv): return set()
    try:
        df = pd.read_csv(output_csv)
        return set(df['url'].dropna().astype(str).str.strip().tolist())
    except Exception as e:
        logger.warning(f"Failed to read existing output: {e}")
        return set()

def write_results_to_csv(results, output_csv, first_batch):
    if not results: return
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    mode = 'a' if os.path.exists(output_csv) else 'w'
    header = first_batch or not os.path.exists(output_csv)
    pd.DataFrame(results).to_csv(output_csv, mode=mode, header=header, index=False)
    logger.info(f"Saved {len(results)} results to {output_csv}")

# --- Main ---
async def main(input_csv: str, output_csv: str):
    if not os.path.exists(input_csv):
        logger.error(f"Input not found: {input_csv}")
        return

    df = pd.read_csv(input_csv)
    if "url" not in df.columns or "http_status" not in df.columns:
        logger.error("Missing 'url' or 'http_status' columns")
        return

    basename = os.path.basename(input_csv)
    output_csv = os.path.join(os.path.dirname(output_csv), basename)
    processed = get_processed_urls(output_csv)
    df = df[~df['url'].astype(str).str.strip().isin(processed)]
    if df.empty:
        logger.info("All URLs processed")
        return

    logger.info(f"Processing {len(df)} URLs...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    first_batch = True

    with ThreadPoolExecutor(max_workers=5) as executor:
        for i in range(0, len(df), BATCH_SIZE):
            batch = df.iloc[i:i+BATCH_SIZE]
            tasks = [process_single_url(row, executor, semaphore) for _, row in batch.iterrows()]
            results = await asyncio.gather(*tasks)
            write_results_to_csv(results, output_csv, first_batch)
            first_batch = False

    logger.info(f"Completed: {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract network features from URLs in a CSV file.")
    parser.add_argument("--input", required=True, help="Path to the input CSV file containing URLs.")
    parser.add_argument("--output", required=True, help="Path to the output directory to save extracted features.")
    args = parser.parse_args()

    # --- SAFETY: Ensure output is a proper directory path ---
    input_path = args.input.strip()
    output_dir = args.output.strip()

    if not os.path.exists(input_path):
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    if not os.path.isfile(input_path):
        logger.error(f"Input is not a file: {input_path}")
        sys.exit(1)

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Build output path
    input_filename = os.path.basename(input_path)
    output_csv = os.path.join(output_dir, input_filename)

    logger.info(f"Processing {input_path} → {output_csv}")

    asyncio.run(main(input_path, output_csv))