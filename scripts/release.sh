#!/usr/bin/env bash
set -euo pipefail

# Pretty output helpers
info()  { printf '\033[1;34m›\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m✓\033[0m %s\n' "$1"; }
err()   { printf '\033[1;31m✗\033[0m %s\n' "$1" >&2; }

# Parse flags: --no-checks skips linting and testing
run_checks=true
for arg in "$@"; do
  case "$arg" in
    --no-checks) run_checks=false ;;
    *) err "Unknown argument: $arg"; exit 1 ;;
  esac
done

# 0. Must be on main
branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "main" ]]; then
  err "You are on '$branch', not 'main'. Switch with: git checkout main"
  exit 1
fi
ok "On branch main"

# 1. Pick the version bump
echo "Which version bump?"
select choice in "alpha (prerelease)" "patch" "minor" "major"; do
  case "$choice" in
    "alpha (prerelease)") bump="prerelease"; preid="--preid=alpha"; tag="--tag alpha"; break ;;
    "patch")              bump="patch";      preid="";              tag="";            break ;;
    "minor")              bump="minor";      preid="";              tag="";            break ;;
    "major")              bump="major";      preid="";              tag="";            break ;;
    *) echo "Invalid choice, try again." ;;
  esac
done
ok "Selected: $bump"

# 2. Logged in to npm?
if ! npm whoami >/dev/null 2>&1; then
  err "Not logged in to npm. Run: npm login"
  exit 1
fi
ok "npm user: $(npm whoami)"

# 3. Clean working tree?
if [[ -n "$(git status --porcelain)" ]]; then
  err "Working tree is not clean. Commit or stash your changes first:"
  git status --short
  exit 1
fi
ok "Working tree is clean"

# 4. Lint + test (unless skipped)
if [[ "$run_checks" == "true" ]]; then
  info "Linting…"
  npm run lint
  ok "Lint passed"

  info "Testing…"
  npm test
  ok "Tests passed"
else
  info "Skipping lint and tests (--no-checks)"
fi

# 5. Build
info "Building…"
rm -rf dist
npm run build
ok "Build complete"

# 6. Bump version (creates commit + git tag v<version>)
info "Bumping version ($bump)…"
new_version="$(npm version "$bump" $preid -m "chore: release v%s")"
ok "Version is now ${new_version}"

# 7. Publish (prerelease goes under the alpha dist-tag)
info "Publishing to npm…"
npm publish $tag
ok "Published ${new_version}${tag:+ ($tag)}"

# 8. Push commit + tag to GitHub
info "Pushing to origin/main with tags…"
git push origin main --follow-tags
ok "Pushed ${new_version} to GitHub"

ok "Release complete 🎉"



