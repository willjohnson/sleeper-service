#!/bin/sh
# Compiles the admin UI stylesheet from src/sleeper_service/ui/tailwind.css.
#
# Tailwind emits only the utility classes it finds in the templates, so rerun
# this after changing template markup. Extra arguments pass through to the
# Tailwind CLI, e.g. `scripts/build_css.sh --watch` while editing templates.
#
# The version is pinned here because pytailwindcss otherwise downloads the
# latest release, and CI checks that the committed stylesheet matches a fresh
# build — a floating version would fail that check on every Tailwind release.
set -eu
export TAILWINDCSS_VERSION=v4.3.3
cd "$(dirname "$0")/.."
exec uv run tailwindcss \
  -i src/sleeper_service/ui/tailwind.css \
  -o src/sleeper_service/ui/static/style.css \
  --minify "$@"
