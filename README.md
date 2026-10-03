# pihole-blocklist

One Pi-hole blocklist, assembled from **72 upstream lists** and cleaned into a
single file. Two URLs: one for everything, one for 18+.

```
https://github.com/alphingj/pihole-blocklist/releases/latest/download/allinone.txt
https://github.com/alphingj/pihole-blocklist/releases/latest/download/adult.txt
```

Paste the first into *Settings → Lists → Add a new subscribed list* and run
`pihole -g`. That is the whole install.

---

## What you get

| List | Domains | Size | What it is |
| --- | ---: | ---: | --- |
| [`allinone.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/allinone.txt) | 5,251,316 | 139 MiB | **Everything except 18+** — the main list |
| [`adult.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/adult.txt) | 5,496,225 | 175 MiB | **18+ only** — porn, adult, shock, gambling |
| [`core.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/core.txt) | 4,776,476 | 126 MiB | ads + malware + phishing |
| [`junk.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/junk.txt) | 3,190,234 | 81 MiB | tracking + scam + crypto + spam |
| [`sensitive.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/sensitive.txt) | 5,894,547 | 186 MiB | spyware + gambling + adult |
| [`everything.txt`](https://github.com/alphingj/pihole-blocklist/releases/latest/download/everything.txt) | 10,757,754 | 315 MiB | all of the above, unsplit — for archival use |

Also published: `allinone.domains.txt` (bare domains, 99 MiB),
`allinone.adblock.txt` (`||domain^`, 114 MiB), `allinone.txt.gz` (33 MiB) and
`SHA256SUMS`.

Every `.txt` is in `hosts` format, one `0.0.0.0 domain` per line, sorted with
`LC_ALL=C` and deduplicated.

### The three groups

Lists overlap — `core`, `junk` and `sensitive` are cuts of the same union, not
disjoint buckets. Subscribe to `allinone` for all of it, or pick the groups you
actually want:

| Group | Categories | Sources |
| --- | --- | ---: |
| `core` | `ads`, `malware`, `phishing` | 46 |
| `junk` | `tracking`, `scam`, `crypto`, `spam` | 22 |
| `sensitive` | `spyware`, `gambling`, `adult` | 8 |

Which upstream list lands in which group is one line per source in
[`sources.toml`](sources.toml). Full breakdown in [SOURCES.md](SOURCES.md).

---

## Install

### Pi-hole v6 / v5, web interface

*Settings → Lists → Add a new subscribed list*, paste the URL, comment it
`allinone`, leave the group on `Default`, save, then:

```sh
pihole -g
```

Add `adult.txt` the same way if you want the 18+ list too.

### Pi-hole, config file

```sh
sudo tee -a /etc/pihole/adlist.yaml >/dev/null <<'EOF'
---
adlists:
  - https://github.com/alphingj/pihole-blocklist/releases/latest/download/allinone.txt
  - https://github.com/alphingj/pihole-blocklist/releases/latest/download/adult.txt
EOF
sudo pihole -g
```

### Pi-hole in Docker

Same URLs in the web interface, or add them to your `pihole.conf`'s
`FTL_QUERYLOG_FLUSH_INTERVAL` section's gravity list via the web UI — the
release URLs are ordinary HTTPS and need no special handling.

### Other resolvers

The `allinone.txt` URL serves a plain `hosts` file, so anything that reads one
works:

```sh
# dnsmasq — point addn-hosts at a local copy
curl -sSLO https://github.com/alphingj/pihole-blocklist/releases/latest/download/allinone.txt
echo "addn-hosts=/etc/dnsmasq.d/pihole-blocklist.txt" | sudo tee -a /etc/dnsmasq.conf
sudo systemctl restart dnsmasq

# unbound — blocklist, expects one domain per line
echo 'blocklist: "/var/lib/unbound/pihole-blocklist.domains"' | sudo tee -a /etc/unbound/unbound.conf
curl -sSL https://github.com/alphingj/pihole-blocklist/releases/latest/download/allinone.domains.txt \
  | sudo tee /var/lib/unbound/pihole-blocklist.domains >/dev/null
sudo systemctl restart unbound

# a plain hosts file
sudo cp allinone.txt /etc/hosts
```

Use `allinone.adblock.txt` for anything that speaks Adblock syntax (uBlock,
AdGuard apps). AdGuard Home does not fetch remote blocklists on its own — feed it
`allinone.domains.txt` through a scheduled `curl` into its filters file.

---

## Before you subscribe, read this

**It is big.** FTL keeps the gravity list in memory; budget on the order of
300–400 bytes per domain, so 5.25 M domains is roughly 1.5–2 GB. On a Pi with
1 GB, either use `core.txt`/`junk.txt` instead, or pick fewer upstream lists.
`pihole -g` on the first run will also take a while and use disk for the
download.

**It will cost you 139 MiB per update,** once a week, and only when the lists
actually changed: the release assets send an `ETag`, and Pi-hole's `gravity.sh`
stores it and sends `If-None-Match`, so an unchanged list transfers 0 bytes. The
publishing workflow deliberately skips a release when the content hash is
identical, so you are never forced to re-download the same bytes.

**Some things will break.** `crypto` and `scam` lists contain domains that
double as legitimate services. When something breaks, add it to Pi-hole's
allowlist (`pihole -g` after `pihole --allow` style edits, or the *Allowlist*
tab) and open an issue so the list can be narrowed.

**18+ is a separate list on purpose.** `allinone.txt` is scrubbed of adult
content so it is safe to hand to a shared or family machine. The guarantee is
enforced in two independent ways and measured in
[`data/overlap.json`](data/overlap.json):

| Filter | Domains removed from `allinone.txt` |
| --- | ---: |
| exact — also present in `adult.txt` | 46,857 |
| keyword — `porn`, `xxx`, `hentai`, `escort`, `onlyfans`, … | 10,213 |
| **total, from a 5,308,386 pre-scrub union** | **57,070** |

A sample of all 10,213 keyword removals was audited by hand: every one was
genuinely adult. The exact-match filter removes junk and parking domains
(`001216.xyz`, `00casino.com`, spam pages on `weebly.com` and `blogspot.*`) and
never touches shared infrastructure — `doubleclick.net`,
`googlesyndication.com`, `amazonaws.com`, `cloudfront.net`, `cloudflare.com` and
`jsdelivr.net` are all still in `allinone.txt`.

The cost of the guarantee: a few hundred malware hostnames that live *on* adult
parking domains (`conficker.phimxxxhd.com`) are dropped from `allinone.txt`.
They are in `adult.txt` instead. That is the trade, and it is deliberate.

---

## How it is built

```
sources.toml  ──▶  fetch  ──▶  parse/normalise  ──▶  union  ──▶  scrub  ──▶  emit
  72 sources       323 MB        10.8 M domains      sort -u    18+ filter   hosts
                   upstream       from 322 MB         -m         2 nets       format
```

`scripts/build.py`, standard library only, ~4 minutes for a cold build:

1. **fetch** — 69 enabled sources in parallel, cached in `dist/raw/`.
2. **parse** — one normaliser for every format the wild contains: `hosts`
   (`0.0.0.0 d`, `127.0.0.1 d`, `::1 d`), bare domains, Adblock (`||d^`,
   `||d^$third-party`, `@@` allow-rules), dnsmasq (`address=/d/`), and URLs
   (reduced to their host). Everything is lowercased, trailing dots and `*.`
   stripped, and IDNs converted to punycode (`keró.hu` → `xn--ker-hia.hu`).
3. **union** — per-source output is already sorted, so each list is a single
   `sort -u -m` over its members.
4. **scrub** — the 18+ filtering above, only on lists that should not contain it.
5. **emit** — `0.0.0.0 domain`, plus the domain/adblock/gzip variants.
6. **smoke test** — the build *fails* if any output contains a loopback name, an
   IP literal, Adblock syntax, a dotless entry, a non-ASCII character, an adult
   keyword in a non-adult list, a duplicate, or an out-of-order line.

### What the parser throws away, and why

Every rejection is counted by reason and sampled in
[`data/rejected.txt`](data/rejected.txt) — about 3,900 lines in total. The
interesting ones:

| Reason | Lines | Example |
| --- | ---: | --- |
| `bad-label` | 1,847 | `bimqut238p64emywajhvaw==` (base64 junk), `-wps.com.cn^` |
| `ip-alias-line` | 598 | `::1 ip6-localhost`, `ff02::1 ip6-allnodes`, `fe80::1%lo0 localhost` |
| `hyphen-run` | 292 | wildcard-expansion artefacts |
| `single-label` | 250 | `adult`, `porn`, `http`, `bestbuycom`, `casinoonline-com` |
| `too-many-labels` | 224 | `a.a.a.a.a.a.a.a.a.a.a.myniceposts.com` |
| `bad-tld` | 173 | `://account.booking.xn--`, `axr7hs51.$unp2idvalk.digital` |
| `wildcard` | 138 | `://message1*.z13.web.core.windows.net^` |
| `blocked-name` | 47 | `localhost`, `broadcasthost`, `ip6-loopback` |
| `allow-rule` | 9 | `@@\|\|safe.example^` |
| `idna-failed` | 1 | `םv` |

**`blocked-name` is the one that matters.** Most combined lists built by
`cat`-ing and stripping `0.0.0.0` carry `localhost`, `localhost.localdomain`,
`ip6-localhost`, `ip6-loopback` and `broadcasthost` into the blocklist, because
those lines live in several popular upstream hosts files. Blocking `localhost`
breaks local name resolution and can take Pi-hole's own web interface with it.
This parser drops them, along with `*.local`, `*.arpa`, `*.test`, `*.invalid`,
`*.internal` and `*.example`.

### What this fixed versus a naive concatenation

Measured against a 7,163,737-line combined list built the usual way (cat,
strip the IP prefix, sort, uniq) from the same 71 sources:

| | Count |
| --- | ---: |
| In both | 7,139,786 |
| **Recovered — present here, missing from the naive list** | **3,617,968** |
| Dropped — Adblock rules, comments, base64 junk, loopback names | 23,951 |

The naive parse lost domains because most of the largest modern lists
(`hagezi/tif`, `oisd`, `hagezi/pro.plus`, `hagezi/gambling`) are in Adblock
format, not `hosts` format, and a prefix-strip does not understand `||domain^`.

### Sources

72 upstream lists, 69 enabled. Three are switched off in `sources.toml` with the
reason recorded next to them:

| Source | Why it is off |
| --- | --- |
| `osint.digitalside.it` | dead — the host no longer resolves, project retired |
| `paulgb/BarbBlock` | stale — last updated 2019-05-26 |
| `hagezi/hoster` | blocks entire hosting providers; the author calls it overkill for most setups |

One was added: `nsfw.oisd.nl` (471 k entries, updated hourly) for `adult.txt`.

Two category caveats worth knowing: `hagezi/spam-tlds` blocks *TLDs*, which
cannot be expressed in a Pi-hole domain list, so only its 10 two-label entries
survive; and `sensitive.txt` is 8 sources wide, so it is mostly the 18+ list
with spyware on top.

Per-source detail, license and live fetch status: [SOURCES.md](SOURCES.md).

---

## Keeping it current

| | |
| --- | --- |
| Rebuild | weekly, Mondays, by GitHub Actions |
| Source liveness | daily; a dead source fails the build and files an issue |
| Publishing | only when the content hash changed, so subscribers are not made to re-download identical bytes |

Reproduce a build yourself — no dependencies beyond Python 3.11+:

```sh
python3 scripts/build.py --refresh     # fetch, parse, union, scrub, emit, smoke test
python3 scripts/check_sources.py       # is everything still reachable?
./scripts/publish.sh                   # publish, unless nothing changed
```

To add, remove or re-categorise a source, edit [`sources.toml`](sources.toml) and
rebuild. See [CONTRIBUTING.md](CONTRIBUTING.md).

Verify a download:

```sh
sha256sum -c SHA256SUMS
```

---

## License

The tooling in this repository — `scripts/`, the workflows, `sources.toml` — is
MIT, see [LICENSE](LICENSE).

The blocklists themselves are an aggregation of other people's work. Each
upstream list keeps its own terms, credited per source in
[SOURCES.md](SOURCES.md); several are GPL or CC BY and require attribution and
share-alike if you redistribute the derived list. Check the upstream terms
before you republish `allinone.txt` commercially.

Thanks to everyone maintaining the upstream lists — HaGeZi, firebog/WaLLy3K,
StevenBlack, the abuse.ch team, oisd, the AdGuard team, Disconnect, and the
Pi-hole community lists that have been refining this for a decade.
