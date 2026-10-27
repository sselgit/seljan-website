#!/usr/bin/env bash
# Publish the site/ folder to the gh-pages branch, which GitHub Pages serves at seljan.net.
# Run from the repo root after committing your changes on main and pushing them.
#
# This builds a new gh-pages commit whose contents equal site/, on top of the current
# remote gh-pages tip. That is a normal fast-forward push, no force needed.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "Commit your changes first." >&2
  exit 1
fi

git fetch -q origin gh-pages
base=$(git rev-parse origin/gh-pages)
tree=$(git rev-parse "main:site")

if [ "$(git rev-parse "$base^{tree}")" = "$tree" ]; then
  echo "gh-pages already matches site/. Nothing to publish."
  exit 0
fi

commit=$(git commit-tree "$tree" -p "$base" -m "Publish site to gh-pages")
git push origin "$commit:refs/heads/gh-pages"
echo "Published. GitHub Pages usually updates within a minute or two."
