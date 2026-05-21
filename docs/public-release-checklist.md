# Public Release Checklist

Use this before making the repository public or publishing an example release.

## Secrets And Generated Files

- `.env` is not committed.
- `certs/` is not committed.
- `generated_sites/*.json` is not committed unless a sample was deliberately
  reviewed and sanitized.
- Root-level generated files such as `local-default.json` and model-output JSON
  dumps are not committed.
- Logs under `honeybot/`, Docker volumes, and `analysis/output/` are not
  committed.
- Any key, token, database password, or certificate used during testing has been
  rotated.

## Safety

- The README safety note is preserved.
- `SECURITY.md` is present and accurate.
- Example commands bind the orchestrator admin API to localhost.
- Public examples do not include real IPs, real credentials, or identifiable
  captured traffic.

## Project Presentation

- README badges render.
- `docs/assets/logo.svg` and `docs/assets/demo.gif` render in GitHub.
- Quick Start commands are still current.
- The default branch passes the smoke workflow.
- License and contribution guidance are present.

## Recommended Smoke Commands

```bash
python3 -m py_compile generator/generate_multi_route.py generator/sitegen/*.py
python3 generator/generate_multi_route.py \
  --provider ollama \
  --context ai-company \
  --count 0 \
  --models smoke-model
python3 -m json.tool generator/contexts/ai_company.json >/dev/null
```
