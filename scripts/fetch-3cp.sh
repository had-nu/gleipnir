#!/bin/sh
# Fetch the 3CP specification into .3cp/ so it is available to read offline.
#
# Hierarchy, from the protocol outward:
#
#   1. The 3CP RFC is the source of truth.
#   2. spec/SPEC-3CP-V2.md is the normative spec: an implementation *attempt* that must
#      follow the RFC structurally. Where spec and RFC disagree, the RFC wins.
#   3. Gleipnir implements the spec. Where Gleipnir is more efficient than the spec
#      anticipated, that is legitimate — but it must be documented and heavily tested
#      before being reflected back into the RFC. A silent divergence is not allowed.
#
# The spec is deliberately NOT vendored here: a second copy drifts from the first, and a
# stale copy is worse than none. Five defects here were diagnosed by reading code instead
# of the canon; this script exists so the canon is one command away rather than an
# assumption.
#
#   ./scripts/fetch-3cp.sh          # fetch or refresh
#   ./scripts/fetch-3cp.sh --check  # verify the cached copy is present
#
# Requires gh (authenticated) or curl to raw.githubusercontent.com.
#
# SPEC-3CP-V2.md is the canonical file — the 3CP README calls it "Current normative
# specification" and CONTRIBUTING.md routes every normative change to it. 3CP-v2.md is a
# second, newer document whose §4.3 contradicts the canonical one on the VRF construction
# and whose §6.4 contradicts §6.2 on the post-abort alpha. Both are fetched so the
# disagreement stays visible rather than being resolved silently.

set -eu

REPO="had-nu/3CP"
SPEC="spec"
OUT=".3cp"
FILES="SPEC-3CP-V2.md 3CP-v2.md 3CP.md glossary.md"
CANON="SPEC-3CP-V2.md"

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
  grep -c '\[MUST\]' "$OUT/$CANON" | sed "s|^|  $CANON MUSTs: |"
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
echo "Cite $OUT/$CANON. It is the normative spec; 3CP-v2.md is a second document that"
echo "disagrees with it in places — §4.3 (VRF construction) and §6.4 (post-abort alpha)."
echo "Verify every quote against the canon before writing it into a comment — Rule 2 of"
echo "docs/VERIFICATION-PLAYBOOK.md."