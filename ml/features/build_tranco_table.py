"""Build offline Tranco rank bucket lookup table."""

import json
from pathlib import Path
from urllib.request import Request, urlopen
import io, zipfile

DEST = Path(__file__).resolve().parent / "data" / "tranco_buckets.json"

def build():
    DEST.parent.mkdir(parents=True, exist_ok=True)
    url = "https://tranco-list.eu/download/daily/top-1m.csv.zip"
    print(f"Fetching Tranco for offline lookup: {url}")
    req = Request(url, headers={"User-Agent": "Scamurai-Builder/1.0"})
    with urlopen(req, timeout=60) as resp:
        raw = resp.read()
    
    zf = zipfile.ZipFile(io.BytesIO(raw))
    name = zf.namelist()[0]
    text = zf.read(name).decode("utf-8")
    
    buckets = {}
    for line in text.splitlines():
        line = line.strip()
        if "," in line:
            parts = line.split(",", 1)
            rank = int(parts[0])
            domain = parts[1].strip().lower()
            if rank <= 1000:
                buckets[domain] = 1
            elif rank <= 10000:
                buckets[domain] = 2
            elif rank <= 100000:
                buckets[domain] = 3
            elif rank <= 500000:
                buckets[domain] = 4
            else:
                break # Cap at top 500k to keep file size reasonable
                
    # Also add key Indian banking and service domains explicitly
    indian_services = {
        "onlinesbi.sbi": 2, "irctc.co.in": 2, "incometax.gov.in": 2, "digilocker.gov.in": 2,
        "npci.org.in": 2, "paytm.com": 2, "phonepe.com": 2, "hdfcbank.com": 2,
        "icicibank.com": 2, "axisbank.com": 2, "kotak.com": 2, "uidai.gov.in": 2,
        "flipkart.com": 2, "jiomart.com": 2, "jio.com": 2, "airtel.in": 2,
        "indiapost.gov.in": 2, "gem.gov.in": 2, "passportindia.gov.in": 2,
        "chatgpt.com": 1, "claude.ai": 1, "openai.com": 1, "anthropic.com": 1,
    }
    for d, b in indian_services.items():
        if d not in buckets:
            buckets[d] = b

    with open(DEST, "w", encoding="utf-8") as f:
        json.dump(buckets, f, separators=(",", ":"))
    print(f"Wrote {len(buckets)} domains to {DEST} ({DEST.stat().st_size // 1024} KB)")

if __name__ == "__main__":
    build()
