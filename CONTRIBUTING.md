# Contributing

Thanks for helping make heiLLMpot better. This project is research-oriented, so
the most valuable contributions are small, reviewable changes that improve
clarity, safety, reproducibility, or realism.

Please follow the project [Code of Conduct](CODE_OF_CONDUCT.md) in issues,
pull requests, and discussions.

## Good First Contributions

- New generator contexts in `generator/contexts/`
- Prompt improvements that reduce broken HTML or generic content
- README and docs fixes
- Analysis queries and reporting improvements
- Focused runtime fixes in `honeybot/` or `orchestrator/`

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install requests tqdm
```

For the C++ services, use the Docker Compose flow:

```bash
make up
make logs
make down
```

## Smoke Checks

Before opening a pull request, run:

```bash
python3 -m py_compile generator/generate_multi_route.py generator/sitegen/*.py
python3 generator/generate_multi_route.py \
  --provider ollama \
  --context ai-company \
  --count 0 \
  --models smoke-model
```

If your change touches Docker, nginx, the orchestrator, or honeybot runtime,
also run the relevant Compose target locally.

## Style

- Keep generated assets, logs, certificates, and secrets out of git.
- Prefer small files with explicit responsibilities.
- Follow existing project patterns before adding new abstractions.
- Document new generator flags in both the README and `docs/generator.md`.
- Keep safety language clear and visible.

## Pull Requests

Please include:

- What changed
- Why it changed
- How you tested it
- Any operational or safety impact

Do not include real attack traffic, real credentials, private IP data from
third-party environments, or generated sites that have not been reviewed.
