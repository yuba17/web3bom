#!/usr/bin/env python3
"""
Solodit FULL Database Downloader
Downloads ALL 50K+ findings from Solodit API via empty-keyword pagination.
Rate limit: 20 req/min, pageSize=100 → ~510 requests → ~26 min

Usage: python3 solodit_download_all.py [--resume] [--content-limit 2000]
Output: knowledge/solodit_all_findings.jsonl (one JSON object per line, ~100MB)

Requires: CYFRIN_API_KEY in .env or environment
"""

import json, time, os, sys, argparse
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
OUTPUT_DIR = Path(__file__).parent.parent  # knowledge/
PROGRESS_FILE = OUTPUT_DIR / "solodit_download_progress.json"
OUTPUT_FILE = OUTPUT_DIR / "solodit_all_findings.jsonl"

def load_api_key():
    key = os.environ.get("CYFRIN_API_KEY")
    if key:
        return key
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("CYFRIN_API_KEY="):
                return line.split("=", 1)[1].strip()
    print("ERROR: Set CYFRIN_API_KEY in .env or environment")
    sys.exit(1)

def fetch_page(api_key, page, page_size=100, impact=None):
    url = "https://solodit.cyfrin.io/api/v1/solodit/findings"
    filters = {"keywords": "", "sortField": "Quality", "sortDirection": "Desc"}
    if impact:
        filters["impact"] = impact if isinstance(impact, list) else [impact]
    payload = json.dumps({"page": page, "pageSize": page_size, "filters": filters}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Cyfrin-API-Key', api_key)

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            if attempt < 2:
                print(f"  Retry {attempt+1}/3: {e}", file=sys.stderr)
                time.sleep(5 * (attempt + 1))
            else:
                print(f"  FAILED page {page}: {e}", file=sys.stderr)
                return None

def extract_finding(f, content_limit):
    """Extract essential fields from a finding."""
    return {
        "id": f.get("id", ""),
        "title": f.get("title", ""),
        "impact": f.get("impact", ""),
        "slug": f.get("slug", ""),
        "content": (f.get("content") or "")[:content_limit],
        "summary": (f.get("summary") or "")[:500],
        "firm": f.get("firm_name", ""),
        "protocol": f.get("protocol_name", ""),
        "report_date": f.get("report_date", ""),
        "quality_score": f.get("quality_score", 0),
        "tags": [t.get("tag", {}).get("name", "") for t in (f.get("issues_issuetagscore") or []) if t.get("tag", {}).get("name")],
    }

def save_progress(page, total_saved, total_pages):
    PROGRESS_FILE.write_text(json.dumps({
        "last_page": page,
        "total_saved": total_saved,
        "total_pages": total_pages,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }))

def load_progress():
    if PROGRESS_FILE.exists():
        return json.loads(PROGRESS_FILE.read_text())
    return None

def main():
    parser = argparse.ArgumentParser(description="Download ALL Solodit findings")
    parser.add_argument("--resume", action="store_true", help="Resume from last saved progress")
    parser.add_argument("--content-limit", type=int, default=2000, help="Max chars of content per finding")
    parser.add_argument("--impact", default=None, help="Filter by impact: HIGH, MEDIUM, LOW (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="Just check total count")
    args = parser.parse_args()

    api_key = load_api_key()

    # Get total count
    result = fetch_page(api_key, 1, page_size=1)
    if not result:
        print("ERROR: Could not connect to API")
        sys.exit(1)

    meta = result.get("metadata", {})
    total = meta.get("totalResults", 0)
    print(f"Total findings in Solodit: {total:,}")

    if args.dry_run:
        return

    page_size = 100
    total_pages = (total + page_size - 1) // page_size

    # Resume support
    start_page = 1
    total_saved = 0
    seen_ids = set()
    mode = "w"

    if args.resume:
        progress = load_progress()
        if progress:
            start_page = progress["last_page"] + 1
            total_saved = progress["total_saved"]
            mode = "a"
            # Load existing IDs to deduplicate
            if OUTPUT_FILE.exists():
                with open(OUTPUT_FILE) as f:
                    for line in f:
                        try:
                            seen_ids.add(json.loads(line)["id"])
                        except:
                            pass
            print(f"Resuming from page {start_page} ({total_saved:,} already saved)")
        else:
            print("No progress file found, starting fresh")

    request_count = 0

    with open(OUTPUT_FILE, mode) as outf:
        for page in range(start_page, total_pages + 1):
            # Rate limiting: 18 requests then pause (leave 2 buffer)
            if request_count > 0 and request_count % 18 == 0:
                remaining_pages = total_pages - page
                eta_min = (remaining_pages / 18) * 1.1  # ~1.1 min per batch of 18
                print(f"  Rate limit pause (60s)... ETA: {eta_min:.0f} min remaining", flush=True)
                time.sleep(62)

            result = fetch_page(api_key, page, page_size,
                              [args.impact] if args.impact else None)
            request_count += 1

            if not result:
                print(f"  Skipping page {page} (failed)")
                time.sleep(5)
                continue

            findings = result.get("findings", [])
            if not findings:
                print(f"  Page {page}: empty — reached end")
                break

            new_count = 0
            for f in findings:
                fid = f.get("id", "")
                if fid and fid not in seen_ids:
                    seen_ids.add(fid)
                    extracted = extract_finding(f, args.content_limit)
                    outf.write(json.dumps(extracted) + "\n")
                    total_saved += 1
                    new_count += 1

            outf.flush()

            if page % 10 == 0 or page == start_page:
                save_progress(page, total_saved, total_pages)
                pct = (page / total_pages) * 100
                print(f"  Page {page}/{total_pages} ({pct:.1f}%) — {total_saved:,} findings saved", flush=True)

            # Small delay between requests
            time.sleep(3.2)

    save_progress(total_pages, total_saved, total_pages)

    # Summary
    file_size = OUTPUT_FILE.stat().st_size / (1024 * 1024)
    print(f"\n{'='*50}")
    print(f"DONE: {total_saved:,} findings → {OUTPUT_FILE}")
    print(f"File size: {file_size:.1f} MB")
    print(f"Unique IDs: {len(seen_ids):,}")

    # Quick stats
    impacts = {}
    with open(OUTPUT_FILE) as f:
        for line in f:
            try:
                d = json.loads(line)
                imp = d.get("impact", "UNKNOWN")
                impacts[imp] = impacts.get(imp, 0) + 1
            except:
                pass
    print(f"By impact: {json.dumps(impacts)}")

if __name__ == "__main__":
    main()
