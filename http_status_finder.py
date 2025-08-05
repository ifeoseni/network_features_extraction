import os
import re
import ssl
import gc
import asyncio
import logging
import argparse
import pandas as pd
from datetime import datetime
from playwright.async_api import async_playwright
import httpx


# ─── CONFIG ───────────────────────────────────────────────────────────────
MAX_CONCURRENT = 10
REQUEST_TIMEOUT = 15
USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
)
BATCH_SIZE = 500

# Set up logger to also write to file later
log = logging.getLogger("status_checker")
log.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def ensure_scheme(url: str) -> str:
    if not url or not isinstance(url, str) or not url.strip():
        return ""
    url = url.strip()
    return url if re.match(r"https?://", url, re.IGNORECASE) else f"https://{url}"

async def fetch_httpx(client: httpx.AsyncClient, url: str) -> dict:
    try:
        r = await client.get(url, timeout=REQUEST_TIMEOUT)
        return {
            "http_status": r.status_code,
            "is_active": 1,
            "has_redirect": int(bool(r.history)),
            "error": ""
        }
    except Exception as e:
        return {"http_status": 0, "is_active": 0, "has_redirect": 0, "error": str(e)}

async def fetch_playwright(browser, url: str) -> dict:
    page = await browser.new_page(user_agent=USER_AGENT)
    try:
        await page.route("**/*", lambda route, request: (
            route.abort() if request.resource_type in ["image", "stylesheet", "font", "media"] else route.continue_()
        ))
        resp = await page.goto(url, timeout=30000, wait_until="domcontentloaded")
        status = resp.status if resp else 0
        return {
            "http_status": status,
            "is_active": int(bool(status)),
            "has_redirect": 0,
            "error": ""
        }
    except Exception as e:
        return {
            "http_status": 0,
            "is_active": 0,
            "has_redirect": 0,
            "error": str(e)
        }
    finally:
        await page.close()

async def check_url(batch_client, playwright_ctx, browser, sem, row: pd.Series) -> dict:
    url = ensure_scheme(row.get('url', ''))
    async with sem:
        if not url:
            return {**row.to_dict(), "http_status": 0, "is_active": 0, "has_redirect": 0, "error": "Empty or invalid URL"}

        hx = await fetch_httpx(batch_client, url)
        if hx["http_status"] > 0:
            return {**row.to_dict(), **hx}

        if playwright_ctx and browser:
            pw = await fetch_playwright(browser, url)
            if pw["http_status"] == 0 and hx["error"]:
                pw["error"] = hx["error"]
            return {**row.to_dict(), **pw}

        return {**row.to_dict(), **hx}

async def process_batches(df: pd.DataFrame, output_file: str):
    columns = list(df.columns) + ["http_status", "is_active", "has_redirect", "error"]
    pd.DataFrame(columns=columns).to_csv(output_file, index=False)

    total = len(df)
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    playwright_ctx, browser = None, None

    try:
        playwright_ctx = await async_playwright().start()
        browser = await playwright_ctx.chromium.launch(headless=True)

        for batch_start in range(0, total, BATCH_SIZE):
            batch = df.iloc[batch_start:batch_start + BATCH_SIZE]
            log.info(f" Processing rows {batch_start + 1}–{batch_start + len(batch)} of {total}")

            headers = {
                "User-Agent": USER_AGENT,
                "Accept-Encoding": "gzip, deflate, br"
            }
            batch_client = httpx.AsyncClient(
                http2=False,
                follow_redirects=True,
                verify=ssl_ctx,
                headers=headers
            )

            tasks = [check_url(batch_client, playwright_ctx, browser, sem, row) for _, row in batch.iterrows()]
            results = await asyncio.gather(*tasks, return_exceptions=False)

            pd.DataFrame(results).to_csv(output_file, mode="a", header=False, index=False)
            await batch_client.aclose()
            gc.collect()

    finally:
        if browser:
            await browser.close()
        if playwright_ctx:
            await playwright_ctx.stop()

    log.info(f" All batches complete. Results saved to {output_file}")

def main(input_file: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    input_name = os.path.splitext(os.path.basename(input_file))[0]
    output_csv = os.path.join(output_dir, f"{input_name}_results.csv")
    output_log = os.path.join(output_dir, f"{input_name}_log.txt")

    # Write all log output to file
    file_handler = logging.FileHandler(output_log)
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)

    df = pd.read_csv(input_file, engine="python", on_bad_lines="skip", encoding="utf-8")

    asyncio.run(process_batches(df, output_csv))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch-safe HTTP status checker")
    parser.add_argument("--input-file", required=True, help="Path to input CSV")
    parser.add_argument("--output-dir", required=True, help="Directory for output CSV and logs")
    args = parser.parse_args()
    main(args.input_file, args.output_dir)

# python http_status_checker.py --input-file split/PhiUSIIL_cleaned_v2_84001_94000.csv --output-dir http_status/split
# python http_status_checker.py --input-file split/PhiUSIIL_cleaned_v2_134001_144000.csv --output-dir http_status/split
# python http_status_checker.py --input-file split/PhiUSIIL_cleaned_v2_194001_204000.csv --output-dir http_status/split
# python http_status_checker.py --input-file split/Mendeley_cleaned_v2_400001_410000_refuse_to_continue.csv --output-dir http_status/split
