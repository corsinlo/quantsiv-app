#!/bin/bash
# SessionStart hook (.claude/settings.json): installs Python dependencies into .venv, in Claude
# Code cloud sessions only. Local sessions are untouched. It never fails the session.
# The lock files target Python 3.12 (as CI and the Docker image do), so prefer python3.12.

if [ "$CLAUDE_CODE_REMOTE" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR" || exit 0

PYTHON=python3
command -v python3.12 >/dev/null 2>&1 && PYTHON=python3.12

if [ ! -x .venv/bin/python ]; then
  "$PYTHON" -m venv .venv || { echo "install_pkgs: could not create .venv" >&2; exit 0; }
fi

.venv/bin/python -m pip install --quiet --disable-pip-version-check \
  -r requirements.txt -r requirements-dev.txt \
  || echo "install_pkgs: requirements did not install" >&2

exit 0
