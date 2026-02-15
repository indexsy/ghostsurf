#!/bin/bash
# GhostSurf Privacy Browser launcher
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/venv/bin/activate"
python3 "$DIR/browser.py" "$@"
