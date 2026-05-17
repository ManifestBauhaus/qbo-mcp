#!/bin/bash
# Quick re-auth all QBO tokens. Run from anywhere.
# Usage: bash ~/qbo-mcp/scripts/reauth_quick.sh
cd ~/qbo-mcp && uv run python scripts/reauth_all.py "$@"
