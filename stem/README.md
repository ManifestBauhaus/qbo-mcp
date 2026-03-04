# Stem Protocol Mirror — qbo-mcp

This is a local mirror of the Stem blueprint for this repo. The primary source of truth lives at `~/bauhaus-os/stem/qbo-mcp.md`.

## Quick Rebuild

```bash
# 1. Read the full blueprint
cat ~/bauhaus-os/stem/qbo-mcp.md

# 2. Or if bauhaus-os is unavailable, follow these steps:

# Clone
git clone git@github.com:ManifestBauhaus/qbo-mcp.git
cd qbo-mcp
git checkout develop

# Bootstrap (uses uv, not venv/pip)
uv sync

# Configure
cp .env.example .env
# Fill in: QBO_CLIENT_ID, QBO_CLIENT_SECRET

# Place token files (get from GCP Secret Manager or Eric)
# tokens/ecre.json, tokens/bcd.json, tokens/bmr.json

# Verify
uv run python -c "from qbo_mcp.config import config; print('Config OK')"

# Validate
python3 ~/bauhaus-os/stem/validate_stem.py qbo-mcp
```

## Key Info

- **Level:** 3 (Execution)
- **Lead:** Eric
- **GitHub:** ManifestBauhaus/qbo-mcp
- **Default Branch:** develop
- **Purpose:** QuickBooks Online MCP server — 3 books (ECRE, BCD, BMR), 12 financial reporting tools
- **Package Manager:** uv (not pip/venv)
- **MCP Instances:** qbo-ecre, qbo-bcd, qbo-bmr (configured in ~/.claude.json)
- **Intuit App:** "Bauhaus OS" (App ID: dd136ddc-0287-4bed-8a84-d8903001e71a)

For the complete blueprint with directory structure, dependencies, and reconstruction checklist, see `~/bauhaus-os/stem/qbo-mcp.md`.
