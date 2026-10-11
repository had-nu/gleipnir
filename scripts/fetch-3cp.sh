#!/bin/sh
# Fetch the 3CP specification into .3cp/ so it is available to read offline.
#
# The spec is canon and lives at github.com/had-nu/3CP. It is deliberately NOT vendored
# into this repository: a second copy drifts from the first, and a stale copy is worse
# than none. Five defects here were diagnosed by reading code instead of the canon; this
# script exists so the canon is one command away rather than an assumption.
#
#   ./scripts/fetch-3cp.sh          # fetch or refresh
#   ./scripts/fetch-3cp.sh --check  # verify the cached copy is current, do not fetch
#
# Requires gh (authenticated) or curl to raw.githubusercontent.com.
#
# Both language versions are fetched. 3CP-v2.md (EN) is the normative one and is what
# docs/3CP-CONFORMANCE.md cites: the PT file has matching section numbers but differing
# content, so citing the wrong one yields a wrong citation that still looks right.

set -eu

REPO="had-nu/3CP"
SPEC="spec"
OUT=".3cp"
FILES="3CP-v2.md SPEC-3CP-V2.md 3CP.md glossary.md"

mkdir -p "$OUT"

fetch_one() {
  file="$1"
  if command -v gh >/dev/null 2>&1; then
    gh api "repos/$REPO/contents/$SPEC/$file" --jq '.content' 2>/dev/null | base64 -d > "$OUT/$file"
  else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/main/$SPEC/$file" -o "$OUT/$file"
  fi
}

if [ "${1:-}" = "--check" ]; then
  missing=0
  for f in $FILES; do
    if [ ! -s "$OUT/$f" ]; then
      echo "missing: $OUT/$f — run ./scripts/fetch-3cp.sh" >&2
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    exit 1
  fi
  echo "canon cached in $OUT/"
  grep -c '\[MUST\]' "$OUT/3CP-v2.md" | sed 's/^/  3CP-v2.md MUSTs: /'
  exit 0
fi

for f in $FILES; do
  if fetch_one "$f"; then
    printf '  %-20s %s bytes\n' "$f" "$(wc -c < "$OUT/$f" | tr -d ' ')"
  else
    echo "failed to fetch $f" >&2
    exit 1
  fi
done

echo
echo "canon cached in $OUT/"
echo
echo "Cite $OUT/3CP-v2.md. Section numbers match the PT file but contents do not."
echo "Verify every quote before writing it into a comment — see Rule 2 of"
echo "docs/VERIFICATION-PLAYBOOK.md."