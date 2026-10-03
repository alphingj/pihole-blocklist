#!/usr/bin/env python3
"""Build the pihole-blocklist lists from the sources in sources.toml.

Pipeline
    fetch  -> dist/raw/<id>          upstream bytes, cached between runs
    parse  -> dist/norm/<id>.txt     one normalised domain per line, sorted
    union  -> per-list sort -u -m    dedupe across the sources in that list
    scrub  -> exact + keyword adult filtering for the non-18+ lists
    emit   -> dist/<list>.txt        0.0.0.0 <domain>  (hosts format)

stdlib only. No third-party imports, no shell quoting hazards: every external
command is spawned with an argument list.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "sources.toml"
RAW = ROOT / "dist" / "raw"
NORM = ROOT / "dist" / "norm"
DATA = ROOT / "data"

UA = "Mozilla/5.0 (X11; Linux x86_64) pihole-blocklist-builder/1.0"
MAX_DOWNLOAD = 400 * 1024 * 1024
TIMEOUT = 180

IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TLD = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]{2,})$")
HTMLISH = re.compile(rb"^\s*(?:<!doctype html|<html|<head|<\?xml)", re.I)


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------
def load_manifest() -> dict:
    with MANIFEST.open("rb") as fh:
        m = tomllib.load(fh)
    cats = {c for s in m["source"] for c in s["categories"]}
    for group, members in m["groups"].items():
        unknown = set(members) - cats
        if unknown:
            sys.exit(f"group {group}: categories not used by any source: {sorted(unknown)}")
    return m


def enabled_sources(manifest: dict) -> list[dict]:
    return [s for s in manifest["source"] if s.get("enabled", True)]


def sources_for_list(manifest: dict, spec: dict) -> list[dict]:
    """Which sources feed a list, according to its spec in [lists]."""
    out = []
    for src in enabled_sources(manifest):
        if "include_categories" in spec:
            keep = bool(set(src["categories"]) & set(spec["include_categories"]))
        elif "exclude_categories" in spec:
            keep = not (set(src["categories"]) & set(spec["exclude_categories"]))
        elif "all_groups" in spec:
            keep = True
        else:
            wanted = {c for g in spec.get("groups", []) for c in manifest["groups"][g]}
            keep = bool(set(src["categories"]) & wanted)
        if keep:
            out.append(src)
    return out


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------
def fetch_one(src: dict, refresh: bool) -> dict:
    dest = RAW / src["id"]
    if dest.exists() and dest.stat().st_size > 0 and not refresh:
        return {"id": src["id"], "status": "cached", "bytes": dest.stat().st_size}

    req = urllib.request.Request(
        src["url"],
        headers={
            "User-Agent": UA,
            "Accept": "text/plain, */*",
            "Accept-Encoding": "gzip",
        },
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            chunks, total = [], 0
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise ValueError(f"exceeded {MAX_DOWNLOAD} bytes")
                chunks.append(chunk)
        body = b"".join(chunks)
        if resp.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"id": src["id"], "status": "error", "error": f"{type(exc).__name__}: {exc}"}

    if HTMLISH.match(body[:200]):
        head = body[:200].decode("utf-8", "replace").replace("\n", " ")
        return {"id": src["id"], "status": "error", "error": f"looks like HTML: {head[:120]}"}
    if not body.strip():
        return {"id": src["id"], "status": "error", "error": "empty response"}

    dest.write_bytes(body)
    return {
        "id": src["id"],
        "status": "fetched",
        "bytes": len(body),
        "seconds": round(time.time() - started, 1),
    }


def fetch_all(sources: list[dict], refresh: bool, jobs: int) -> dict[str, dict]:
    RAW.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(fetch_one, s, refresh): s for s in sources}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            src = futures[fut]
            results[res["id"]] = res
            mark = {"fetched": "+", "cached": "=", "error": "!"}[res["status"]]
            extra = res.get("error") or f"{res.get('bytes', 0) / 1e6:.1f} MB"
            print(f"  {mark} {src['id']:<32} {extra}", flush=True)
    return results


# --------------------------------------------------------------------------
# parse / normalise
# --------------------------------------------------------------------------
class Normaliser:
    def __init__(self, cfg: dict):
        self.blocked = set(cfg["blocked_names"])
        self.suffixes = tuple(cfg["blocked_suffixes"])
        self.max_labels = cfg["max_labels"]
        self.max_hyphen = cfg["max_hyphen_run"]

    def line(self, raw: str) -> tuple[str | None, str | None]:
        s = raw.strip().lstrip("﻿").strip()
        if not s:
            return None, None
        head = s[0]
        if head in "#!;":
            return None, None
        if head == "[":
            return None, None
        if s.lower().startswith("address=/"):
            return self.domain(s[len("address="):].split("/")[0])
        parts = s.split()
        if len(parts) >= 2 and self._is_ip(parts[0]):
            reason = "ip-alias-line"
            for tok in parts[1:]:
                if self._is_ip(tok):
                    continue
                got, why = self.domain(tok)
                if got:
                    return got, None
                reason = why or reason
            return None, reason
        return self.domain(parts[0])

    @staticmethod
    def _is_ip(tok: str) -> bool:
        t = tok.strip("[]%")
        if IPV4.match(t):
            return True
        return ":" in tok

    def domain(self, tok: str) -> tuple[str | None, str | None]:
        for mark in ("#", "!"):
            if mark in tok:
                tok = tok.split(mark, 1)[0]
        tok = tok.strip().strip("\"'`")
        if not tok:
            return None, "empty"
        if tok.startswith("@@"):
            return None, "allow-rule"

        adblock = tok.startswith("||")
        if adblock:
            tok = tok[2:]
        elif any(c in tok for c in "^|$=<>{}"):
            return None, "adblock-rule"

        if "://" in tok:
            tok = tok.split("://", 1)[1]
        for sep in ("/", "?", "#", ":"):
            if sep in tok:
                tok = tok.split(sep, 1)[0]
        if adblock:
            tok = tok.split("^", 1)[0]
        tok = tok.strip()
        if tok.startswith("*."):
            tok = tok[2:]
        if "*" in tok:
            return None, "wildcard"
        tok = tok.strip(".").lower()
        if not tok:
            return None, "empty-after-strip"
        if len(tok) > 253:
            return None, "too-long"
        if tok in self.blocked:
            return None, "blocked-name"
        if tok.endswith(self.suffixes):
            return None, "blocked-suffix"

        if not tok.isascii():
            try:
                tok = ".".join(lbl.encode("idna").decode("ascii") for lbl in tok.split("."))
            except (UnicodeError, ValueError):
                return None, "idna-failed"
            if len(tok) > 253:
                return None, "too-long"

        labels = tok.split(".")
        if len(labels) < 2:
            return None, "single-label"
        if len(labels) > self.max_labels:
            return None, "too-many-labels"
        for lbl in labels:
            if not LABEL.match(lbl):
                return None, "bad-label"
            if self.max_hyphen + 1 <= len(lbl) and "--" * (self.max_hyphen + 1) in lbl:
                return None, "hyphen-run"
        if not TLD.match(labels[-1]):
            return None, "bad-tld"
        return tok, None


def header_facts(raw_path: Path, limit: int = 60) -> dict:
    """Best-effort title/description/version/license from the top of a list."""
    facts: dict[str, str] = {}
    with raw_path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= limit:
                break
            line = line.strip().lstrip("﻿")
            if not line:
                continue
            for key, pattern in (
                ("title", r"!\s*Title:\s*(.+)|#\s*Title:\s*(.+)|#\s*(.+?blocklist.+?)$"),
                ("description", r"!\s*Description:\s*(.+)"),
                ("version", r"!\s*Version:\s*(.+)"),
                ("updated", r"!\s*Last modified:\s*(.+)"),
                ("license", r"[Ll]icen[cs]e:?\s*(?:https?://\S+\s*)?(\S+)"),
            ):
                if key in facts:
                    continue
                m = re.search(pattern, line)
                if m:
                    val = next((g for g in m.groups() if g), "").strip()
                    if val:
                        facts[key] = val[:200]
            if len(facts) >= 3:
                break
    return facts


def normalise_all(sources: list[dict], cfg: dict) -> dict[str, dict]:
    NORM.mkdir(parents=True, exist_ok=True)
    norm = Normaliser(cfg)
    stats: dict[str, dict] = {}
    for src in sources:
        raw = RAW / src["id"]
        if not raw.exists():
            stats[src["id"]] = {"error": "not downloaded"}
            continue
        rejected: Counter[str] = Counter()
        samples: dict[str, list[str]] = {}
        kept: set[str] = set()
        with raw.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                domain, reason = norm.line(line)
                if domain:
                    kept.add(domain)
                elif reason:
                    rejected[reason] += 1
                    if len(samples.setdefault(reason, [])) < 4:
                        samples[reason].append(line.strip()[:110])
        out = NORM / f"{src['id']}.txt"
        with out.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(kept)) + ("\n" if kept else ""))
        facts = header_facts(raw)
        stats[src["id"]] = {
            "accepted": len(kept),
            "rejected": dict(rejected.most_common()),
            "samples": samples,
            "title": facts.get("title", ""),
            "license_detected": facts.get("license", ""),
            "upstream_version": facts.get("version", "") or facts.get("updated", ""),
            "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
            "raw_bytes": raw.stat().st_size,
        }
        print(
            f"    {src['id']:<32} {len(kept):>9,} kept"
            f"  {sum(rejected.values()):>8,} rejected",
            flush=True,
        )
    return stats


# --------------------------------------------------------------------------
# union, scrub, emit
# --------------------------------------------------------------------------
def run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"command failed: {' '.join(cmd)}\n{proc.stderr}")


def union_files(paths: list[Path], out: Path) -> None:
    existing = [p for p in paths if p.exists() and p.stat().st_size]
    with out.open("wb") as fh:
        if not existing:
            return
        env = dict(os.environ, LC_ALL="C")
        proc = subprocess.run(
            ["sort", "-u", "-m", "--parallel=4", *map(str, existing)],
            stdout=fh,
            env=env,
        )
        if proc.returncode != 0:
            sys.exit(f"sort failed for {out.name}")


def load_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return {ln.strip() for ln in fh if ln.strip()}


def scrub(src: Path, out: Path, adult: set[str], keywords: list[str]) -> dict:
    """Drop adult domains from a non-18+ list.

    net 1 (exact): the domain is also in adult.txt
    net 2 (heuristic): the domain contains an adult keyword
    """
    exact = keyword = 0
    with src.open("r", encoding="utf-8", errors="replace") as fin, out.open(
        "w", encoding="utf-8"
    ) as fout:
        for line in fin:
            dom = line.strip()
            if not dom:
                continue
            if dom in adult:
                exact += 1
                continue
            low = dom.replace(".", "")
            if any(k.replace(".", "") in low for k in keywords):
                keyword += 1
                continue
            fout.write(dom + "\n")
    return {"removed_exact": exact, "removed_keyword": keyword}


def to_hosts(src: Path, dest: Path) -> None:
    with src.open("rb") as fin, dest.open("wb") as fout:
        subprocess.run(["sed", "s|^|0.0.0.0 |"], stdin=fin, stdout=fout, check=True)


def count_lines(path: Path) -> int:
    n = 0
    with path.open("rb") as fh:
        for _ in fh:
            n += 1
    return n


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------
# smoke test
# --------------------------------------------------------------------------
FORBIDDEN = [
    (re.compile(r"^localhost$|^local$|^broadcasthost$|^ip6-"), "loopback name leaked"),
    (re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::|255\.255\.255\.255)\s"), "IP literal as domain"),
    (re.compile(r"[\^|/$=<>\[\]{}%!]"), "rule syntax leaked"),
    (re.compile(r"^[^.]*$"), "no dot (single label)"),
]


def smoke_test(path: Path, expect_no_adult: bool, keywords: list[str]) -> list[str]:
    problems: list[str] = []
    if not path.exists():
        return [f"{path.name}: missing"]
    prev, n = "", 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n += 1
            body = line.rstrip("\n")[8:] if line.startswith("0.0.0.0 ") else line.rstrip("\n")
            if not body:
                problems.append(f"{path.name}:{n}: empty entry")
            for pattern, why in FORBIDDEN:
                if pattern.search(body):
                    problems.append(f"{path.name}:{n}: {why}: {body[:80]}")
                    break
            if expect_no_adult:
                flat = body.replace(".", "")
                hit = next((k for k in keywords if k.replace(".", "") in flat), None)
                if hit:
                    problems.append(f"{path.name}:{n}: adult keyword {hit!r}: {body[:80]}")
            if body < prev:
                problems.append(f"{path.name}:{n}: not sorted: {body[:60]} < {prev[:60]}")
            if body == prev:
                problems.append(f"{path.name}:{n}: duplicate: {body[:60]}")
            prev = body
            if len(problems) > 40:
                problems.append("... more")
                break
    if n == 0:
        problems.append(f"{path.name}: empty file")
    return problems


# --------------------------------------------------------------------------
# generated documentation
# --------------------------------------------------------------------------
def write_sources_txt(manifest: dict) -> None:
    lines = [
        "# pihole-blocklist - upstream blocklist URLs",
        "#",
        "# One URL per line, in the same format Pi-hole's gravity updater and",
        "# pihole-blocklist expect. Generated from sources.toml - edit that file.",
        "#",
        f"# {len(manifest['source'])} sources, "
        f"{len(enabled_sources(manifest))} enabled, "
        f"{len(manifest['source']) - len(enabled_sources(manifest))} disabled.",
        "#",
    ]
    for src in manifest["source"]:
        if not src.get("enabled", True):
            lines.append(f"# disabled: {src['id']} -- {src.get('caution', '')}")
        lines.append(src["url"])
    (ROOT / "sources.txt").write_text("\n".join(lines) + "\n")


def write_sources_md(manifest: dict, stats: dict[str, dict], fetch: dict[str, dict]) -> None:
    groups = manifest["groups"]
    cat_to_group = {c: g for g, cs in groups.items() for c in cs}
    out = [
        "# Sources",
        "",
        "Every upstream list that feeds the generated files, what it is for, and",
        "whether it is currently being served. Generated by `scripts/build.py` from",
        "[`sources.toml`](sources.toml) - edit the manifest, not this file.",
        "",
        "## Categories and groups",
        "",
        "| Group | Categories | Lists |",
        "| --- | --- | --- |",
    ]
    for group, cats in groups.items():
        out.append(f"| `{group}` | {', '.join(f'`{c}`' for c in cats)} | [`{group}.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/{group}.txt) |")
    out += [
        "",
        "## Per-source detail",
        "",
        "| Source | Categories | Group | Enabled | Domains contributed | License | Note |",
        "| --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for src in manifest["source"]:
        sid = src["id"]
        st = stats.get(sid, {})
        cats = ", ".join(f"`{c}`" for c in src["categories"])
        grp = ", ".join(sorted({cat_to_group[c] for c in src["categories"] if c in cat_to_group}))
        on = "yes" if src.get("enabled", True) else "**no**"
        count = f"{st['accepted']:,}" if st.get("accepted") is not None else "n/a"
        lic = src.get("license") or st.get("license_detected") or "not stated upstream"
        note = src.get("caution") or src.get("note") or ""
        out.append(
            f"| [`{sid}`]({src['url']}) | {cats} | {grp} | {on} | {count} | {lic} | {note} |"
        )
    dead = [sid for sid, r in fetch.items() if r.get("status") == "error"]
    out += ["", "## Fetch status", ""]
    if dead:
        out.append("These sources failed to download on the last build:")
        out.append("")
        for sid in dead:
            out.append(f"- `{sid}`: {fetch[sid].get('error', 'unknown error')}")
    else:
        out.append("All enabled sources downloaded successfully on the last build.")
    (ROOT / "SOURCES.md").write_text("\n".join(out) + "\n")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="re-download even if cached")
    ap.add_argument("--jobs", type=int, default=12, help="parallel downloads (default 12)")
    ap.add_argument("--list", action="append", help="build only these lists (repeatable)")
    ap.add_argument("--reparse", action="store_true", help="skip fetch, re-run the parser on the cache")
    ap.add_argument(
        "--docs-only",
        action="store_true",
        help="re-render sources.txt and SOURCES.md from data/stats.json, no fetch or parse",
    )
    args = ap.parse_args()

    manifest = load_manifest()
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    DATA.mkdir(exist_ok=True)
    sources = enabled_sources(manifest)
    keywords = manifest["adult_scrub"]["keywords"]
    cfg = manifest["parser"]

    if args.docs_only:
        write_sources_txt(manifest)
        cached = json.loads((DATA / "stats.json").read_text())
        write_sources_md(
            manifest,
            {k: v for k, v in cached.get("sources", {}).items()},
            {k: v for k, v in cached.get("sources", {}).items()},
        )
        print("re-rendered sources.txt and SOURCES.md from data/stats.json")
        return 0

    write_sources_txt(manifest)
    print(f"manifest: {len(manifest['source'])} sources, {len(sources)} enabled")

    fetch: dict[str, dict] = {}
    if args.reparse:
        fetch = {
            s["id"]: {"status": "cached" if (RAW / s["id"]).exists() else "error",
                      "error": "not downloaded"}
            for s in sources
        }
    else:
        print(f"\nfetching {len(sources)} sources ({args.jobs} at a time)")
        fetch = fetch_all(sources, args.refresh, args.jobs)
        failed = [s for s, r in fetch.items() if r["status"] == "error"]
        if failed:
            print(f"\n{len(failed)} source(s) failed: {', '.join(sorted(failed))}")
            if not any((RAW / f).exists() for f in failed):
                print("nothing to parse; run again with --refresh once the network is back")
                return 1

    print("\nparsing and normalising")
    stats = normalise_all(sources, cfg)

    adult_srcs = [
        s for s in sources
        if {"adult", "gambling"} & set(s["categories"])
    ]
    adult_union = dist / "_adult_union.txt"
    union_files([NORM / f"{s['id']}.txt" for s in adult_srcs], adult_union)
    adult = load_set(adult_union)
    adult_union.unlink(missing_ok=True)
    print(f"\nadult reference set: {len(adult):,} domains from {len(adult_srcs)} source(s)")

    wanted = args.list or list(manifest["lists"])
    summary: dict[str, dict] = {}
    overlap: dict[str, dict] = {}
    for name in wanted:
        spec = manifest["lists"][name]
        members = sources_for_list(manifest, spec)
        print(f"\n[{name}] {len(members)} source(s)")
        union = dist / f"_{name}.union.txt"
        union_files([NORM / f"{s['id']}.txt" for s in members], union)
        pre = count_lines(union)
        cleaned = union
        if spec.get("scrub_adult"):
            scrubbed = dist / f"_{name}.clean.txt"
            counts = scrub(union, scrubbed, adult, keywords)
            cleaned = scrubbed
            overlap[name] = {"before_scrub": pre, **counts}
            print(f"  scrubbed adult: {counts['removed_exact']:,} exact + "
                  f"{counts['removed_keyword']:,} keyword")
        out = dist / f"{name}.txt"
        to_hosts(cleaned, out)
        n = count_lines(out)
        summary[name] = {
            "entries": n,
            "bytes": out.stat().st_size,
            "sha256": sha256(out),
            "sources": [s["id"] for s in members],
            "scrubbed": spec.get("scrub_adult", False),
        }
        print(f"  {name}.txt: {n:,} domains, {out.stat().st_size / 1e6:.1f} MB")
        union.unlink(missing_ok=True)
        if cleaned is not union:
            cleaned.unlink(missing_ok=True)

    if (dist / "allinone.txt").exists() and "allinone" in summary:
        with (dist / "allinone.txt").open("rb") as fin, (dist / "allinone.domains.txt").open("wb") as fout:
            for line in fin:
                fout.write(line[8:])
        with (dist / "allinone.txt").open("r", encoding="utf-8") as fin, (
            dist / "allinone.adblock.txt"
        ).open("w", encoding="utf-8") as fout:
            for line in fin:
                fout.write("||" + line[8:].rstrip("\n") + "^\n")
        with (dist / "allinone.txt").open("rb") as fin, gzip.open(dist / "allinone.txt.gz", "wb", 6) as fout:
            shutil.copyfileobj(fin, fout)
        summary["allinone.variants"] = {
            k: {
                "bytes": (dist / f"allinone.{k}.txt").stat().st_size,
                "sha256": sha256(dist / f"allinone.{k}.txt"),
            }
            for k in ("domains", "adblock")
        }
        summary["allinone.variants"]["gz"] = {
            "bytes": (dist / "allinone.txt.gz").stat().st_size,
            "sha256": sha256(dist / "allinone.txt.gz"),
        }

    sums = dist / "SHA256SUMS"
    sums.write_text(
        "".join(
            f"{v['sha256']}  {k}.txt\n"
            for k, v in summary.items()
            if isinstance(v, dict) and "sha256" in v
        )
        + "".join(
            f"{v['sha256']}  {'allinone.txt.gz' if k == 'gz' else f'allinone.{k}.txt'}\n"
            for k, v in summary.get("allinone.variants", {}).items()
        )
    )

    (DATA / "stats.json").write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "lists": summary,
                "adult_reference_entries": len(adult),
                "sources": {s["id"]: {**fetch.get(s["id"], {}), **stats.get(s["id"], {})} for s in manifest["source"]},
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    (DATA / "overlap.json").write_text(json.dumps(overlap, indent=1, sort_keys=True) + "\n")

    rejected_lines = ["# Rejected during parsing, sampled 4 per reason.", "# Generated by scripts/build.py.", ""]
    for sid, st in sorted(stats.items()):
        if not st.get("rejected"):
            continue
        rejected_lines.append(f"## {sid}  ({sum(st['rejected'].values()):,} lines dropped)")
        for reason, count in st["rejected"].items():
            rejected_lines.append(f"  {reason}: {count:,}")
            for sample in st.get("samples", {}).get(reason, []):
                rejected_lines.append(f"      | {sample}")
        rejected_lines.append("")
    (DATA / "rejected.txt").write_text("\n".join(rejected_lines) + "\n")

    write_sources_md(manifest, stats, fetch)

    print("\nsmoke test")
    problems: list[str] = []
    for name in summary:
        if not isinstance(summary[name], dict) or "sha256" not in summary[name]:
            continue
        spec = manifest["lists"][name]
        problems += smoke_test(dist / f"{name}.txt", spec.get("scrub_adult", False), keywords)
    for line in problems[:20]:
        print(f"  FAIL {line}")
    if not problems:
        print("  all lists clean")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
