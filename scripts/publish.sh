#!/usr/bin/env bash
# Publish dist/ as a GitHub release, but only when the content actually changed.
#
# Why this exists: Pi-hole's gravity.sh stores an ETag for every subscribed list
# and sends If-None-Match on the next run. Cutting a fresh release with an
# identical allinone.txt changes the asset's ETag, which makes every Pi-hole
# that subscribes to it re-download ~146 MB for nothing. So: compare the SHA-256
# of what is on disk with what the latest release already serves, and exit early
# when they match.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="${REPO:-alphingj/pihole-blocklist}"
DIST="dist"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

command -v gh >/dev/null || { echo "gh not installed"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated"; exit 1; }

[ -f "${DIST}/allinone.txt" ] || { echo "no ${DIST}/allinone.txt -- run scripts/build.py first"; exit 1; }

local_sum=$(sha256sum "${DIST}/allinone.txt" | cut -d' ' -f1)
echo "local allinone.txt sha256: ${local_sum}"

remote_sum=$(curl -sSL --max-time 60 "${BASE_URL}/SHA256SUMS" 2>/dev/null \
  | awk '$2=="allinone.txt"{print $1; exit}') || true

if [ "${remote_sum}" = "${local_sum}" ]; then
  echo "latest release already serves this exact list -- nothing to publish"
  exit 0
fi
if [ -n "${remote_sum}" ]; then
  echo "content changed (was ${remote_sum})"
else
  echo "no previous release found -- publishing for the first time"
fi

VERSION="${VERSION:-v$(date -u +%Y.%m.%d)}"
ENTRIES=$(wc -l < "${DIST}/allinone.txt" | tr -d ' ')
ADULT_ENTRIES=$(wc -l < "${DIST}/adult.txt" | tr -d ' ')

assets=(
  "${DIST}/allinone.txt"
  "${DIST}/allinone.domains.txt"
  "${DIST}/allinone.adblock.txt"
  "${DIST}/allinone.txt.gz"
  "${DIST}/adult.txt"
  "${DIST}/core.txt"
  "${DIST}/junk.txt"
  "${DIST}/sensitive.txt"
  "${DIST}/everything.txt"
  "${DIST}/SHA256SUMS"
)
for a in "${assets[@]}"; do
  [ -f "$a" ] || { echo "missing asset: $a"; exit 1; }
done

notes=$(cat <<EOF
Automated build from \`${REPO}\`.

| List | Domains | Size |
| --- | ---: | ---: |
| \`allinone.txt\` | ${ENTRIES} | $(du -h "${DIST}/allinone.txt" | cut -f1) |
| \`adult.txt\` | ${ADULT_ENTRIES} | $(du -h "${DIST}/adult.txt" | cut -f1) |

Subscribe in Pi-hole under *Settings -> Lists -> Add a new subscribed list*:

\`\`\`
${BASE_URL}/allinone.txt
${BASE_URL}/adult.txt
\`\`\`

\`allinone.txt\` is everything except 18+ content. \`adult.txt\` is the 18+ list.
Both are in \`hosts\` format (\`0.0.0.0 domain\`). SHA-256 of this build's main list:

\`\`\`
${local_sum}
\`\`\`
EOF
)

echo "creating release ${VERSION}"
gh release create "${VERSION}" "${assets[@]}" \
  --repo "${REPO}" \
  --title "${VERSION}" \
  --notes "${notes}"

echo
echo "published:"
for a in "${assets[@]}"; do
  printf '  %s\n' "${BASE_URL}/$(basename "$a")"
done
