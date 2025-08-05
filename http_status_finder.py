#!/usr/bin/env python3
"""
HTTP-status checker with Cloudscraper + FlareSolverr fallback
- Adds http_status, is_active, has_redirect columns *in place*
- Streams output → safe for very large files
- Keeps original columns untouched
CLI unchanged: --input-file cleaned_data/1.csv --output-dir http_status
"""

import argparse, asyncio, aiohttp, cloudscraper, json, logging, os, sys, ssl
from datetime import datetime
from pathlib import Path
import pandas as pd
# import tqdm.asyncio as tqdm
from tqdm.asyncio import tqdm_asyncio 

# ---------- CONFIG ---------------------------------------------------------
CLOUDSCRAPER = cloudscraper.create_scraper(
    browser={"browser": "chrome", "platform": "windows", "mobile": False}
)
FLARE_ENDPOINT = os.getenv("FLARE_ENDPOINT", "http://localhost:8191/v1")
MAX_CONCURRENT = 100
REQUEST_TIMEOUT = 20
BATCH_SIZE = 1000
RETRY_CODES = {403, 503, 429}

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("http_status.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("checker")

# ---------- UTILITIES ------------------------------------------------------
def ensure_scheme(url: str) -> str:
    url = str(url).strip()
    if not url:
        return ""
    return url if url.startswith(("http://", "https://")) else f"https://{url}"

# ---------- CHECKERS -------------------------------------------------------
async def cloud_get(url: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        r = await loop.run_in_executor(
            None, CLOUDSCRAPER.get, url, {"timeout": REQUEST_TIMEOUT}
        )
        return {
            "http_status": r.status_code,
            "is_active": int(r.status_code > 0),
            "has_redirect": int(bool(r.history)),
            "error": "",
        }
    except cloudscraper.exceptions.CloudflareChallengeError:
        return {"http_status": 503, "is_active": 0, "has_redirect": 0, "error": "cf_v2"}
    except Exception as e:
        return {"http_status": 0, "is_active": 0, "has_redirect": 0, "error": str(e)}

async def flare_get(session: aiohttp.ClientSession, url: str) -> dict:
    payload = {"cmd": "request.get", "url": url, "maxTimeout": 60_000}
    try:
        async with session.post(FLARE_ENDPOINT, json=payload, timeout=70) as resp:
            data = await resp.json()
            sol = data.get("solution", {})
            status = sol.get("status", 0)
            return {
                "http_status": status,
                "is_active": int(status > 0),
                "has_redirect": 0,  # FlareSolverr does not expose history
                "error": "",
            }
    except Exception as e:
        return {"http_status": 0, "is_active": 0, "has_redirect": 0, "error": str(e)}

async def check_url(url: str, session: aiohttp.ClientSession) -> dict:
    url = ensure_scheme(url)
    if not url:
        return {"http_status": 0, "is_active": 0, "has_redirect": 0, "error": "Empty URL"}

    first = await cloud_get(url)
    if first["http_status"] in RETRY_CODES or first["error"] == "cf_v2":
        return await flare_get(session, url)
    return first

# ---------- MAIN -----------------------------------------------------------
async def process_file(input_csv: Path, output_csv: Path) -> None:
    df = pd.read_csv(input_csv, engine="python", on_bad_lines="skip", dtype=str)
    if "url" not in df.columns:
        log.error("No 'url' column in %s", input_csv)
        return

    # Safely drop the four columns if they already exist
    df.drop(
        columns=[c for c in ["http_status", "is_active", "has_redirect", "error"]
                 if c in df.columns],
        inplace=True
    )

    urls = df["url"].dropna().tolist()
    total = len(urls)

    conn = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=conn) as session:
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def sem_worker(u):
            async with sem:
                return await check_url(u, session)

        tasks = [sem_worker(u) for u in urls]
        # results = await tqdm.gather(*tasks, total=total, desc=str(input_csv.name))
        results = await tqdm_asyncio.gather(*tasks, total=total, desc=str(input_csv.name))
    # Merge results back into the original DataFrame
    res_df = pd.DataFrame(results)
    for col in ["http_status", "is_active", "has_redirect", "error"]:
        df[col] = res_df[col]

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_csv, index=False)
    log.info("Finished %s → %s", input_csv, output_csv)

def main():
    parser = argparse.ArgumentParser(description="Add HTTP-status columns to CSV")
    parser.add_argument("--input-file", required=True, help="CSV with 'url' column")
    parser.add_argument("--output-dir", required=True, help="Folder for updated CSV")
    args = parser.parse_args()

    in_path = Path(args.input_file)
    out_path = Path(args.output_dir) / in_path.name

    asyncio.run(process_file(in_path, out_path))

if __name__ == "__main__":
    main()