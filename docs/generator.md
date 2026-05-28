# Generator Guide

The generator creates JSON site definitions consumed by the honeybot. Each
definition includes web routes, generated HTML, server fingerprint metadata,
TLS profile data, users, fake credentials, and an SSH environment profile.

## Basic Usage

```bash
python generator/generate_multi_route.py \
  --provider ollama \
  --models llama3.2:3b \
  --count 1 \
  --context ai-company \
  --country US \
  --language English
```

Output files are written to `generated_sites/`.

## Interactive Mode

```bash
python generator/generate_multi_route.py --interactive
```

Keyboard shortcuts:

| Key | Action |
| --- | --- |
| Arrow keys / `j` / `k` | Move through fields |
| Left / right / space | Cycle choices |
| Enter | Edit text fields |
| `s` / F10 | Start generation |
| `q` / Esc | Cancel |

## Providers

| Provider | Key/env | Example model |
| --- | --- | --- |
| Ollama | none | `llama3.2:3b` |
| OpenAI | `OPENAI_API_KEY` | `gpt-5-mini` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` |
| Google Gemini | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `gemini-2.5-flash` |

Hosted providers can also use `--api-key`, but environment variables are safer
for shell history and public demos.

## Agent Depth

| Depth | Behavior |
| --- | --- |
| `basic` | App spec, route generation, critic/revision, SSH profile |
| `standard` | Adds UX/product architect planning |
| `deep` | Adds final realism QA for every generated page |

Use `deep` when you want more polished examples and are comfortable spending
more model time. Use `basic` for quick local smoke tests.

## Contexts

Built-in contexts live in `generator/contexts/`:

- `university`
- `hospital`
- `bank`
- `corporate`
- `government`
- `ai_company`

Aliases for the AI company context include `ai`, `ai-company`, `llm-provider`,
and `model-provider`.

You can provide a custom context file:

```bash
python generator/generate_multi_route.py \
  --context generator/contexts/custom.json \
  --models llama3.2:3b \
  --count 1
```

Custom context files can define:

- `context_name`
- `org_types`
- `user_roles`
- `name_style`
- `brand_color`
- `logo_url`
- `reference_organizations`
- `prompt_guidance`
- `os_options`
- `ssh_banner_options`
- `tls_country`

## Quality Controls

- `--temperature` controls spec and SSH profile creativity.
- `--max-output-tokens` defaults to `8192` to reduce truncated HTML from larger
  local models.
- The site-wide HTML contract keeps generated links inside known routes, adds
  responsive guard CSS, and sends malformed markup back through revision.
- If any route still cannot produce valid HTML, generation aborts instead of
  saving a partial site.

## Public Demo Hygiene

Generated sites may contain intentionally fake credentials and realistic-looking
domains. Review generated files before sharing screenshots or committing
examples. By default, `generated_sites/*.json` is ignored.
