#!/usr/bin/env bash
# Checks that internal/workloadauth is a byte-for-byte copy of the canonical
# package in sneakers-vault at the commit pinned in proto-refs.env. The copy
# is refreshed by bumping SNEAKERS_VAULT_REF and copying the files again.
#
# SNEAKERS_VAULT_DIR points at a local sneakers-vault checkout instead, for
# trying an unmerged change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/proto-refs.env"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -n "${SNEAKERS_VAULT_DIR:-}" ]]; then
  echo "workloadauth: sneakers-vault from $SNEAKERS_VAULT_DIR"
  cp -R "$SNEAKERS_VAULT_DIR/internal/workloadauth" "$work/workloadauth"
else
  echo "workloadauth: sneakers-vault at $SNEAKERS_VAULT_REF"
  curl -sSfL "https://codeload.github.com/Sneakers-PAM/sneakers-vault/tar.gz/$SNEAKERS_VAULT_REF" |
    tar -xz -C "$work" --strip-components=2 --wildcards '*/internal/workloadauth/*'
fi

if ! diff -r "$work/workloadauth" "$root/internal/workloadauth"; then
  echo "internal/workloadauth differs from sneakers-vault at $SNEAKERS_VAULT_REF; copy it again" >&2
  exit 1
fi
echo "workloadauth: identical"
