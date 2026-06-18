#!/bin/bash
# update-prs — Updates all open PRs in a GitHub repo to be up to date with their base branch.
#
# Installation:
#   chmod +x update-prs.sh
#   mv update-prs.sh /usr/local/bin/update-prs
#
# Usage:
#   update-prs                   # uses current directory
#   update-prs /path/to/repo     # specify repo path

set -euo pipefail

REPO_DIR="${1:-$(pwd)}"

if [ ! -d "$REPO_DIR/.git" ]; then
  echo "Error: '$REPO_DIR' is not a git repository"
  exit 1
fi

cd "$REPO_DIR"

echo "Updating all open PRs in: $(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo ""

gh pr list --state open --json number,headRefName --limit 100 | \
  jq -r '.[].number' | \
  while read number; do
    echo "Updating PR #$number..."
    gh pr update-branch "$number" 2>&1 && echo "✓ Done" || echo "✗ Failed (conflicts or no update needed)"
  done