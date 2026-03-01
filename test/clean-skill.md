# git-summary skill
# A legitimate skill that summarizes recent git activity.
# This file should produce a PASS result from the scanner.

## Description
Displays a formatted summary of recent git commits, branch status, and
pending changes in the current repository.

## Usage
- `claw git-summary` — Show last 10 commits and branch status
- `claw git-summary --since 7d` — Show commits from the last 7 days

## install.sh

```bash
#!/bin/bash
set -euo pipefail

# Verify git is available
if ! command -v git &>/dev/null; then
  echo "Error: git is not installed" >&2
  exit 1
fi

echo "git-summary installed successfully."
```

## git-summary.sh

```bash
#!/bin/bash
# git-summary.sh — Show recent git activity

set -euo pipefail

SINCE="${1:---since=7.days.ago}"
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "not a git repo")
REMOTE=$(git remote get-url origin 2>/dev/null || echo "no remote")

echo "Branch:  $BRANCH"
echo "Remote:  $REMOTE"
echo ""
echo "Recent commits:"
git log --oneline --decorate --graph $SINCE 2>/dev/null | head -20

echo ""
echo "Status:"
git status --short 2>/dev/null | head -20

echo ""
echo "Stashes:"
git stash list 2>/dev/null | head -5 || echo "(none)"
```

## git-summary.js (optional Node formatter)

```javascript
// Formats git log output as a table
// Runs only when --format=table is passed

const { spawnSync } = require('child_process');

const args = process.argv.slice(2);
const since = args.find((a) => a.startsWith('--since=')) ?? '--since=7.days.ago';

const result = spawnSync('git', ['log', '--oneline', '--decorate', since], {
  encoding: 'utf8',
  // No shell: true — safe invocation with array args
});

if (result.error) {
  console.error('git log failed:', result.error.message);
  process.exit(1);
}

const lines = result.stdout.trim().split('\n').filter(Boolean);
console.log(`\nFound ${lines.length} commits since filter applied:\n`);
lines.forEach((line, i) => {
  const [hash, ...rest] = line.split(' ');
  console.log(`  ${String(i + 1).padStart(3)}.  ${hash}  ${rest.join(' ')}`);
});
```

## Configuration

No secrets, API keys, or external network calls are made by this skill.
All output is printed to stdout for the user to review.
