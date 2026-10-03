#!/bin/bash
# SessionStart hook (.claude/settings.json): installs Python dependencies into .venv, in Claude
# Code cloud sessions only. Local sessions are untouched. It never fails the session: until
# remediation package WP1 fixes requirements.txt, the install is expected to fail.

if [ "$CLAUDE_CODE_REMOTE" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR" || exit 0

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv || { echo "install_pkgs: could not create .venv" >&2; exit 0; }
fi

for req in requirements.txt requirements-dev.txt; do
  if [ -f "$req" ]; then
    .venv/bin/python -m pip install --quiet --disable-pip-version-check -r "$req" \
      || echo "install_pkgs: $req did not install (expected until WP1 fixes the pins)" >&2
  fi
done

exit 0
