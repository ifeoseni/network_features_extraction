_#!/usr/bin/env python3
"""
Robust Network Feature Extractor
Uses cloudscraper & selenium-stealth to bypass bot protection
Extracts SSL, DNS, WHOIS, HTML, Security Headers, Cookies
"""

import asyncio
import cloudscraper
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
import re
import time
import logging
import os
from concurrent.futures import ThreadPoolExecutor
import whois
import tldextract
import ssl
import socket
import pandas as pd
from typing import Dict, Any, Optional, Tuple
import argparse
import sys
import dns.asyncresolver
import dns.exception
import traceback

# --- Configuration ---
CONCURRENCY_LIMIT = 15  # Lower due to cloudscraper sync nature
REQUEST_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
WHOIS_TIMEOUT = 15
DNS_TIMEOUT = 5
DNS_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
SSL_TIMEOUT = 10
BATCH_SIZE = 20
MAX_RETRIES = 3

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("network_features.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- Network Feature Defaults ---
NETWORK_FEATURE_DEFAULTS = {
    # DNS
    "dns_a_presence": None, "dns_a_count": None,
    "dns_mx_presence": None, "dns_mx_count": None,
    "dns_txt_presence": None, "dns_txt_count": None,
    "dns_ns_presence": None, "dns_ns_count": None,
    "dns_spf_presence": None, "dns_spf_count": None,
    "dns_dkim_presence": None, "dns_dkim_count": None,
    "dns_dmarc_presence": None, "dns_dmarc_count": None,
    # SSL
    "has_ssl_certificate": None, "ssl_certificate_valid": None,
    "ssl_days_to_expiry": None, "ssl_is_expired": None,
    "ssl_is_self_signed": None, "ssl_has_chain_issues": None,
    "ssl_hostname_mismatch": None, "ssl_connection_error": None,
    # WHOIS
    "domain_age_days": None, "time_to_expiration": None,
    # HTTP/HTML
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
    # Security Headers
    "has_xss_protection": None, "has_csp": None,
    "has_hsts": None, "has_x_frame_options": None,
    "has_x_content_type_options": None,
    "has_referrer_policy": None, "has_feature_policy": None,
    # Cookies
    "has_cookie": None, "has_http_only_cookie": None, "has_secure_cookie": None,
}

# --- Helper Functions ---
def ensure_url_scheme(url: str) -> str:
    if not isinstance(url, str):
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return f"http://{url}"
    return url

def get_registered_domain(url: str) -> Optional[str]:
    try:
        if not isinstance(url, str) or not url.strip():
            return None
        url = url.strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            extracted = tldextract.extract(url)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
            url = f"http://{url}"
        parsed = urlparse(url)
        netloc = parsed.netloc.split(":")[0]
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", netloc):
            return netloc
        extracted = tldextract.extract(netloc)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return netloc or None
    except Exception as e:
        logger.warning(f"Domain extraction error for {url}: {e}")
        return None

def get_hostname_from_url(url: str) -> Optional[str]:
    try:
        url = ensure_url_scheme(url.strip())
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
            return None
        return hostname or None
    except Exception as e:
        logger.warning(f"Hostname extraction error for {url}: {e}")
        return None

def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        return False
    if domain.lower() in ["localhost", "127.0.0.1"]:
        return False
    if len(domain) > 253:
        return False
    return True

# --- SSL Functions ---
def matches_hostname(cert_hostname: str, actual_hostname: str) -> bool:
    cert_hostname = cert_hostname.lower()
    actual_hostname = actual_hostname.lower()
    if cert_hostname == actual_hostname:
        return True
    if cert_hostname.startswith("*."):
        base_domain = cert_hostname[2:]
        if actual_hostname.count(".") == base_domain.count(".") + 1 and actual_hostname.endswith("." + base_domain):
            return True
    return False

async def check_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    ssl_features = {
        "has_ssl_certificate": 0, "ssl_certificate_valid": 0,
        "ssl_days_to_expiry": -1, "ssl_is_expired": 0,
        "ssl_is_self_signed": 0, "ssl_has_chain_issues": 0,
        "ssl_hostname_mismatch": 0, "ssl_connection_error": 0,
    }
    if not hostname:
        ssl_features["ssl_connection_error"] = 1
        return ssl_features

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=context),
            timeout=SSL_TIMEOUT
        )
        ssl_features.update({"has_ssl_certificate": 1, "ssl_certificate_valid": 1})
        peercert = writer.get_extra_info('peercert')
        if peercert:
            await parse_ssl_certificate(peercert, hostname, ssl_features)
        writer.close()
        await writer.wait_closed()
        return ssl_features
    except ssl.SSLCertVerificationError as e:
        ssl_features["ssl_certificate_valid"] = 0
        msg = str(e).lower()
        if 'hostname mismatch' in msg:
            ssl_features["ssl_hostname_mismatch"] = 1
        if 'expired' in msg:
            ssl_features["ssl_is_expired"] = 1
        if 'self-signed' in msg:
            ssl_features["ssl_is_self_signed"] = 1
        if 'verify failed' in msg:
            ssl_features["ssl_has_chain_issues"] = 1
    except (ConnectionRefusedError, OSError, socket.gaierror, asyncio.TimeoutError):
        ssl_features["ssl_connection_error"] = 1
    except Exception as e:
        logger.debug(f"SSL error for {hostname}: {e}")
        ssl_features["ssl_connection_error"] = 1
    return ssl_features

async def parse_ssl_certificate(peercert: dict, hostname: str, ssl_features: dict):
    try:
        expire_str = peercert.get('notAfter')
        if expire_str:
            expire_date = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            expire_date = expire_date.replace(tzinfo=timezone.utc)
            now_utc = datetime.now(timezone.utc)
            days_to_expiry = (expire_date - now_utc).days
            ssl_features["ssl_days_to_expiry"] = days_to_expiry
            if days_to_expiry < 0:
                ssl_features["ssl_is_expired"] = 1

        issuer = dict(x[0] for x in peercert.get('issuer', []))
        subject = dict(x[0] for x in peercert.get('subject', []))
        if issuer.get('commonName') == subject.get('commonName') and \
           issuer.get('organizationName') == subject.get('organizationName'):
            ssl_features["ssl_is_self_signed"] = 1

        subject_alt_names = [ext[1] for ext in peercert.get('subjectAltName', []) if ext[0] == 'DNS']
        common_name = subject.get('commonName', '')
        all_names = [common_name] + subject_alt_names
        if not any(matches_hostname(name, hostname) for name in all_names):
            ssl_features["ssl_hostname_mismatch"] = 1
    except Exception as e:
        logger.warning(f"Error parsing SSL cert for {hostname}: {e}")

async def fetch_ssl_cert(url: str) -> Dict[str, Any]:
    hostname = get_hostname_from_url(url)
    return await check_ssl_certificate(hostname, 443) if hostname else {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("ssl_")}

# --- DNS Functions ---
async def fetch_dns_records(domain: str) -> Dict[str, Any]:
    results = {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("dns_")}
    if not is_valid_domain(domain):
        return results

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT * 2
    resolver.nameservers = DNS_RESOLVERS

    record_types = {
        "A": ("dns_a_presence", "dns_a_count"),
        "MX": ("dns_mx_presence", "dns_mx_count"),
        "TXT": ("dns_txt_presence", "dns_txt_count"),
        "NS": ("dns_ns_presence", "dns_ns_count"),
    }

    try:
        for rdtype, (presence_key, count_key) in record_types.items():
            try:
                answer = await resolver.resolve(domain, rdtype, raise_on_no_answer=False)
                if answer.rrset:
                    results[presence_key] = 1
                    results[count_key] = len(answer.rrset)
                    if rdtype == "TXT":
                        root_txt_records = answer
                else:
                    results[presence_key] = 0
                    results[count_key] = 0
            except Exception:
                results[presence_key] = 0
                results[count_key] = 0

        # SPF
        spf_count = 0
        if 'root_txt_records' in locals():
            for r in root_txt_records.rrset:
                txt_data = b"".join(r.strings).lower()
                if b"v=spf1" in txt_data:
                    spf_count += 1
            results["dns_spf_presence"] = 1 if spf_count > 0 else 0
            results["dns_spf_count"] = spf_count
        else:
            results["dns_spf_presence"] = 0
            results["dns_spf_count"] = 0

        # DKIM
        try:
            dkim_domain = f"default._domainkey.{domain}"
            answer = await resolver.resolve(dkim_domain, "TXT", raise_on_no_answer=False)
            results["dns_dkim_presence"] = 1 if answer.rrset else 0
            results["dns_dkim_count"] = len(answer.rrset) if answer.rrset else 0
        except Exception:
            results["dns_dkim_presence"] = 0
            results["dns_dkim_count"] = 0

        # DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answer = await resolver.resolve(dmarc_domain, "TXT", raise_on_no_answer=False)
            dmarc_count = 0
            if answer.rrset:
                for r in answer.rrset:
                    txt_data = b"".join(r.strings).lower()
                    if b"v=dmarc1" in txt_data:
                        dmarc_count += 1
            results["dns_dmarc_presence"] = 1 if dmarc_count > 0 else 0
            results["dns_dmarc_count"] = dmarc_count
        except Exception:
            results["dns_dmarc_presence"] = 0
            results["dns_dmarc_count"] = 0

    except Exception as e:
        logger.error(f"DNS error for {domain}: {e}")
    return results

# --- WHOIS ---
def fetch_whois(domain: str) -> Tuple[Optional[int], Optional[int]]:
    age_days = None
    expiry_days = None
    if not is_valid_domain(domain):
        return age_days, expiry_days
    try:
        w = whois.whois(domain)
        def extract_date(field):
            if isinstance(field, list):
                field = [d for d in field if isinstance(d, datetime)]
                return min(field) if field else None
            return field if isinstance(field, datetime) else None

        creation = extract_date(w.creation_date)
        expiry = extract_date(w.expiration_date)
        now = datetime.now(timezone.utc)

        if creation and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        if creation and creation <= now:
            age_days = (now - creation).days
        if expiry:
            expiry_days = (expiry - now).days
    except Exception as e:
        logger.debug(f"WHOIS failed for {domain}: {e}")
    return age_days, expiry_days

async def fetch_whois_async(domain: str, executor: ThreadPoolExecutor) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    age, expiry = await loop.run_in_executor(executor, fetch_whois, domain)
    return {"domain_age_days": age, "time_to_expiration": expiry}

# --- HTML Features using cloudscraper ---
def fetch_html_features_sync(url: str) -> Dict[str, Any]:
    features = {k: None for k in NETWORK_FEATURE_DEFAULTS if k.startswith("has_") or "num_" in k or k in ["response_time", "content_length", "redirect_count", "final_url_diff", "title_length"]}
    try:
        scraper = cloudscraper.create_scraper(
            browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False}
        )
        start_time = time.time()
        url_with_scheme = ensure_url_scheme(url)
        response = scraper.get(url_with_scheme, timeout=REQUEST_TIMEOUT, allow_redirects=True)

        features["response_time"] = time.time() - start_time
        features["redirect_count"] = len(response.history)
        final_url = response.url
        features["final_url_diff"] = 1 if final_url.lower() != url_with_scheme.lower() else 0

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        security_headers = {
            "x-xss-protection": "has_xss_protection",
            "content-security-policy": "has_csp",
            "strict-transport-security": "has_hsts",
            "x-frame-options": "has_x_frame_options",
            "x-content-type-options": "has_x_content_type_options",
            "referrer-policy": "has_referrer_policy",
            "feature-policy": "has_feature_policy"
        }
        for h, f in security_headers.items():
            features[f] = 1 if h in headers_lower else 0

        if response.cookies:
            features["has_cookie"] = 1
            for cookie in response.cookies:
                if hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr("HttpOnly"):
                    features["has_http_only_cookie"] = 1
                if cookie.secure:
                    features["has_secure_cookie"] = 1

        html_text = response.text
        features["content_length"] = len(response.content)
        soup = BeautifulSoup(html_text, "lxml")

        title = soup.find("title")
        if title and title.get_text(strip=True):
            features["has_title"] = 1
            features["title_length"] = len(title.get_text(strip=True))

        features.update({
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
            "has_submit": 1 if (soup.find("input", type="submit") or soup.find("button", type="submit")) else 0,
            "has_button": 1 if soup.find("button") else 0,
        })

        favicon_selectors = [
            {"rel": "icon"}, {"rel": "shortcut icon"},
            {"href": lambda x: x and "favicon" in x.lower()}
        ]
        features["has_favicon"] = 1 if any(soup.find("link", **sel) for sel in favicon_selectors) else 0

    except Exception as e:
        logger.warning(f"HTML fetch failed for {url}: {e}")
    return features

async def fetch_html_features(url: str, executor: ThreadPoolExecutor) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(executor, fetch_html_features_sync, url)

# --- Main Processing ---
async def process_single_url(row: pd.Series, executor: ThreadPoolExecutor, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    async with semaphore:
        url = str(row.get("url", "")).strip()
        features = NETWORK_FEATURE_DEFAULTS.copy()
        if not url or url.lower() in ["nan", "<na>"]:
            return {**row.to_dict(), **features}

        http_status = row.get("http_status")
        try:
            status_code = int(http_status)
            is_2xx = 200 <= status_code <= 299
        except (TypeError, ValueError):
            is_2xx = False

        if not is_2xx:
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
            for result in results:
                if isinstance(result, Exception):
                    continue
                features.update(result)
        except Exception as e:
            logger.error(f"Processing failed for {url}: {e}")

        return {**row.to_dict(), **features}

# --- Incremental Processing ---
def get_processed_urls(output_csv: str) -> set:
    if not os.path.exists(output_csv):
        return set()
    try:
        df = pd.read_csv(output_csv)
        return set(df['url'].dropna().astype(str).str.strip().tolist())
    except Exception as e:
        logger.warning(f"Could not read existing output: {e}")
        return set()

def write_results_to_csv(results: list, output_csv: str, first_batch: bool):
    if not results:
        return
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    mode = 'a' if os.path.exists(output_csv) else 'w'
    header = first_batch or not os.path.exists(output_csv)
    df = pd.DataFrame(results)
    df.to_csv(output_csv, mode=mode, header=header, index=False)
    logger.info(f"Saved {len(results)} results to {output_csv}")

# --- Main ---
async def main(input_csv: str, output_dir: str):
    if not os.path.exists(input_csv):
        logger.error(f"Input file not found: {input_csv}")
        sys.exit(1)

    df = pd.read_csv(input_csv)
    if "url" not in df.columns or "http_status" not in df.columns:
        logger.error("Input must have 'url' and 'http_status' columns.")
        sys.exit(1)

    basename = os.path.basename(input_csv)
    output_csv = os.path.join(output_dir, basename)
    processed_urls = get_processed_urls(output_csv)
    df = df[~df['url'].astype(str).str.strip().isin(processed_urls)]
    if df.empty:
        logger.info("All URLs already processed.")
        return

    logger.info(f"Processing {len(df)} URLs...")
    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
    first_batch = True

    with ThreadPoolExecutor(max_workers=5) as executor:
        tasks = []
        for _, row in df.iterrows():
            tasks.append(process_single_url(row, executor, semaphore))
            if len(tasks) >= BATCH_SIZE:
                batch_results = await asyncio.gather(*tasks)
                write_results_to_csv(batch_results, output_csv, first_batch)
                first_batch = False
                tasks.clear()
        if tasks:
            batch_results = await asyncio.gather(*tasks)
            write_results_to_csv(batch_results, output_csv, first_batch)

    logger.info(f"Completed. Results saved to: {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract network features from CSV.")
    parser.add_argument("--input", "-i", required=True, help="Input CSV file path")
    parser.add_argument("--output", "-o", required=True, help="Output directory")
    args = parser.parse_args()
    asyncio.run(main(args.input, args.output))