# Contributing

All configuration lives in [`sources.toml`](sources.toml). You should not need to
touch `scripts/build.py` to change what ends up in the lists.

## Add a source

Append a block:

```toml
[[source]]
id = "some-list"                      # short slug, becomes a filename
url = "https://example.com/hosts.txt" # must serve plain text, not HTML
categories = ["ads"]                  # see the table below
```

Then rebuild and check the result:

```sh
python3 scripts/build.py --refresh
python3 scripts/check_sources.py
```

If the source is unreachable, or contributes 0 domains, the build prints why.
`dist/raw/<id>` holds the downloaded bytes, `dist/norm/<id>` what the parser
made of them, and `data/stats.json` the per-source counts.

## Categories

One or more of these, and every category must belong to a group:

| Category | Group | Use it for |
| --- | --- | --- |
| `ads` | `core` | ad servers, ad domains, malvertising |
| `malware` | `core` | malware, botnet, C2, badware |
| `phishing` | `core` | credential theft, PhishTank |
| `tracking` | `junk` | trackers, telemetry, analytics, smart-TV |
| `scam` | `junk` | scams, fraud, warez, fake news |
| `crypto` | `junk` | cryptojacking, crypto exchanges |
| `spam` | `junk` | spam TLDs, referrer spam |
| `spyware` | `sensitive` | stalkerware, spyware |
| `gambling` | `sensitive` | betting |
| `adult` | `sensitive` | porn, adult, shock, gore |

`gambling` and `adult` are the two categories excluded from `allinone.txt` and
shipped as `adult.txt` instead. Adding a source to either one changes what the
18+ list contains — be deliberate about it.

## Disable a source

Do not delete it. Turn it off and say why, so the next person does not
re-add a dead list:

```toml
[[source]]
id = "some-list"
url = "https://example.com/hosts.txt"
categories = ["ads"]
enabled = false
caution = "Dead. example.com stopped serving this in 2026-04."
```

`caution` is required for a disabled source; the build validates that, along
with duplicate ids, duplicate URLs, and categories not covered by a group.

## Good hygiene for a new source

- **Plain text only.** A URL that returns HTML is rejected at fetch time.
- **Prefer a pinned commit** for lists in a git repo, so a bad upstream push
  cannot silently poison the build. `hagezi` publishes through jsDelivr with
  `@latest`, which is acceptable because they are careful.
- **Set `license`** if you know it. Otherwise the build tries to detect it from
  the list header and records "not stated upstream", which is worth fixing.
- **Check the format.** `hosts`, bare domains, `||domain^`, `address=/d/` and
  bare URLs are all understood. TLD-only lists are not: a Pi-hole blocklist
  needs a fully qualified domain, so those entries are dropped.
- **Watch the size.** `hagezi/tif` alone is 48 MB and 2.37 M domains. A source
  that doubles the output needs a reason in its `note`.

## Changing the parser

`Normaliser` in `scripts/build.py` is the whole thing. Two rules:

1. **Never weaken the smoke test to make a build pass.** The checks in
   `smoke_test()` are the difference between a list you can paste into Pi-hole
   and one that quietly blocks `localhost`. If a new source trips a check, fix
   the parser or fix the source.
2. **New rejection reasons need a sample.** `rejected[reason] += 1` plus the
   `samples` dict is what makes `data/rejected.txt` reviewable.

After changing the parser, `--reparse` reruns it over the cached downloads
instead of fetching 323 MB again:

```sh
python3 scripts/build.py --reparse
```
