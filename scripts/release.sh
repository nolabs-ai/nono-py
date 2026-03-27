#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <python-package-version> <nono-crate-version>

Example:
  scripts/release.sh 0.7.1 0.26.0

This script:
  - updates pyproject.toml and Cargo.toml
  - commits the release bump
  - creates tag v<python-package-version>
  - pushes main and the tag
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

version="$1"
nono_version="$2"

if ! [[ "$version" =~ ^[0-9]+(\.[0-9]+)*([.-][A-Za-z0-9]+)*$ ]]; then
  echo "Invalid package version: $version" >&2
  exit 1
fi

if ! [[ "$nono_version" =~ ^[0-9]+(\.[0-9]+)*([.-][A-Za-z0-9]+)*$ ]]; then
  echo "Invalid nono crate version: $nono_version" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -n "$(git status --short)" ]]; then
  echo "Working tree is not clean. Commit or stash changes before releasing." >&2
  exit 1
fi

if git rev-parse --verify "v$version" >/dev/null 2>&1; then
  echo "Tag v$version already exists." >&2
  exit 1
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current_branch" != "main" ]]; then
  echo "Release must be run from main. Current branch: $current_branch" >&2
  exit 1
fi

echo "Preparing release v$version with nono $nono_version"

perl -0pi -e 's/^version = ".*"/version = "'"$version"'"/m' pyproject.toml
perl -0pi -e 's/^version = ".*"/version = "'"$version"'"/m' Cargo.toml
perl -0pi -e 's/^nono = ".*"/nono = "'"$nono_version"'"/m' Cargo.toml
perl -0pi -e 's/^nono-proxy = ".*"/nono-proxy = "'"$nono_version"'"/m' Cargo.toml

git add pyproject.toml Cargo.toml
git commit -m "Release v$version with nono $nono_version"
git tag "v$version"
git push origin main
git push origin "v$version"

echo "Released v$version"
echo "GitHub Actions will publish the package to PyPI from the pushed tag."
