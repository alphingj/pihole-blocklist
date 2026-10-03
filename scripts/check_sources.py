#!/usr/bin/env python3
"""Check every source in sources.toml: is it alive, and has it changed?

    scripts/check_sources.py            human readable table
    scripts/check_sources.py --json     machine readable, for CI

Exits non-zero if an enabled source cannot be fetched, so a scheduled workflow
fails loudly instead of quietly shipping a smaller blocklist.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UA = "Mozilla/5.0 (X11; Linux x86_64) pihole-blocklist-check/1.0"
TIMEOUT = 60


def probe(src: dict) -> dict:
    req = urllib.request.Request(
        src["url"],
        headers={"User-Agent": UA, "Accept": "text/plain, */*", "Accept-Encoding": "gzip"},
    )
    out = {"id": src["id"], "url": src["url"], "enabled": src.get("enabled", True)}
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
    except (urllib.error.URLError, OSError) as exc:
        out["status"] = "dead"
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["status"] = "alive"
    out["bytes"] = len(body)
    out["sha256"] = hashlib.sha256(body).hexdigest()
    if not body.strip():
        out["status"] = "empty"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--only-enabled", action="store_true", default=True)
    ap.add_argument("--all", dest="only_enabled", action="store_false", help="include disabled sources")
    args = ap.parse_args()

    with (ROOT / "sources.toml").open("rb") as fh:
        manifest = tomllib.load(fh)
    sources = [
        s for s in manifest["source"] if args.only_enabled or s.get("enabled", True)
    ]

    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(probe, sources))

    prev = {}
    stats_path = ROOT / "data" / "stats.json"
    if stats_path.exists():
        prev = json.loads(stats_path.read_text()).get("sources", {})

    for r in results:
        r["changed"] = bool(
            r.get("sha256")
            and prev.get(r["id"], {}).get("raw_sha256")
            and prev[r["id"]]["raw_sha256"] != r["sha256"]
        )

    dead = [r for r in results if r["enabled"] and r["status"] != "alive"]
    changed = [r for r in results if r["enabled"] and r["changed"]]

    if args.json:
        print(json.dumps({
            "checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sources": results,
            "dead": [r["id"] for r in dead],
            "changed": [r["id"] for r in changed],
        }, indent=1))
    else:
        print(f"checked {len(results)} sources in {time.time() - started:.1f}s\n")
        print(f"{'source':<32} {'status':<7} {'size':>10}  changed")
        for r in sorted(results, key=lambda x: (x["enabled"], x["status"])):
            size = f"{r['bytes'] / 1e6:.1f} MB" if r.get("bytes") else "-"
            flag = "" if r["enabled"] else "  (disabled)"
            mark = "yes" if r["changed"] else ""
            print(f"{r['id']:<32} {r['status']:<7} {size:>10}  {mark}{flag}")
        print()
        if dead:
            print(f"DEAD ({len(dead)}): " + ", ".join(r["id"] for r in dead))
            for r in dead:
                print(f"  {r['id']}: {r.get('error', 'empty response')}")
        else:
            print("all enabled sources reachable")
        if changed:
            print(f"changed since last build: {', '.join(r['id'] for r in changed)}")

    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())
