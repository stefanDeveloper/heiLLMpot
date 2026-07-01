"""Command-line interface for the honeypot site generator."""

from __future__ import annotations

import argparse
import os

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **_kwargs):
        return iterable

from .clients import (
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    create_llm_client,
    normalize_provider,
)
from .context import build_context
from .pipeline import generate_site


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate honeypot site definitions using LLM providers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate with local Ollama
  %(prog)s --provider ollama --models llama3.2:3b --count 3 \\
            --context hospital --country US --language English

  # Generate with OpenAI
  OPENAI_API_KEY=... %(prog)s --provider openai --models gpt-5-mini \\
            --count 2 --context ai-company --agent-depth deep

  # Generate with Anthropic
  ANTHROPIC_API_KEY=... %(prog)s --provider anthropic \\
            --models claude-sonnet-4-5 --count 2 --context ai-company

  # Generate with Google Gemini
  GEMINI_API_KEY=... %(prog)s --provider google \\
            --models gemini-2.5-flash --count 2 --context ai-company

  # Use a custom context file
  %(prog)s --models llama3.2:3b --count 2 \\
            --context generator/contexts/custom.json
        """,
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch the nmtui-style interactive terminal UI",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default=os.getenv("LLM_PROVIDER", "ollama"),
        help=(
            "LLM provider: ollama, openai, anthropic, google "
            "(aliases: local, oai, claude, gemini). Default: ollama"
        ),
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=None,
        help=(
            "Model names to use (space-separated). Defaults depend on provider: "
            f"{DEFAULT_MODELS}"
        ),
    )
    parser.add_argument(
        "--reasoning-models",
        nargs="+",
        default=None,
        help="Reasoning model names to pair with --models (space-separated). If omitted, falls back to the coding model.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of sites to generate per model (default: 5)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./generated_sites",
        help="Output directory for generated site JSON files",
    )
    parser.add_argument(
        "--context",
        type=str,
        default="university",
        help=(
            "Deployment context: built-in name (university, hospital, bank, "
            "corporate, government, ai_company/ai-company) or path to a "
            "custom context .json file"
        ),
    )
    parser.add_argument(
        "--country",
        type=str,
        default="",
        help=(
            "ISO 3166-1 alpha-2 country code for localization "
            "(e.g. US, DE, FR, JP). Leave empty to let the LLM decide."
        ),
    )
    parser.add_argument(
        "--language",
        type=str,
        default="English",
        help="Natural language for generated UI content (default: English)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.3,
        help="LLM sampling temperature for spec/SSH generation (default: 0.3)",
    )
    parser.add_argument(
        "--vulnerabilities",
        nargs="*",
        default=[],
        metavar="PRESET",
        help=(
            "Enforce specific vulnerability presets "
            "(e.g. idor sql_injection stored_xss). Presets live in "
            "generator/vulnerabilities/. Omit to pick randomly."
        ),
    )

    endpoint_group = parser.add_mutually_exclusive_group()
    endpoint_group.add_argument(
        "--ollama-url",
        dest="ollama_url",
        type=str,
        default=DEFAULT_BASE_URLS["ollama"],
        help="Ollama server base URL (default: http://localhost:11434)",
    )
    endpoint_group.add_argument(
        "--endpoint",
        dest="ollama_url",
        type=str,
        help="Alias for --ollama-url (backward compatibility)",
    )
    parser.add_argument(
        "--api-base-url",
        type=str,
        default=os.getenv("LLM_API_BASE_URL", ""),
        help="Override hosted provider base URL",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default="",
        help=(
            "Hosted provider API key. Prefer env vars: OPENAI_API_KEY, "
            "ANTHROPIC_API_KEY, GEMINI_API_KEY, or GOOGLE_API_KEY."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="HTTP request timeout for provider calls in seconds (default: 300)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Max retries on transient provider errors (default: 3)",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=8192,
        help="Max generated tokens per API call where supported (default: 8192)",
    )
    parser.add_argument(
        "--agent-depth",
        choices=["basic", "standard", "deep"],
        default="standard",
        help=(
            "Generation workflow depth: basic=spec/page/critic flow, "
            "standard=adds UX architect agent, deep=adds final realism QA agent"
        ),
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List available models from the provider and exit",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.interactive:
        from .tui import run_interactive

        args = run_interactive(args)
        if args is None:
            print("Cancelled.")
            return

    try:
        provider = normalize_provider(args.provider)
    except ValueError as e:
        print(f"[!] {e}")
        return

    if not args.models:
        args.models = [DEFAULT_MODELS[provider]]

    base_url = (
        args.ollama_url
        if provider == "ollama"
        else (args.api_base_url or DEFAULT_BASE_URLS[provider])
    )

    try:
        client = create_llm_client(
            provider=provider,
            base_url=base_url,
            api_key=args.api_key,
            timeout=args.timeout,
            max_retries=args.retries,
            max_output_tokens=args.max_output_tokens,
        )
    except ValueError as e:
        print(f"[!] {e}")
        return

    if args.list_models:
        print_model_list(client)
        return

    try:
        ctx = build_context(args.context)
    except (ValueError, FileNotFoundError) as e:
        print(f"[!] {e}")
        return

    print_run_header(args, provider, base_url, ctx.context_name)
    os.makedirs(args.output, exist_ok=True)

    generated = 0
    failed = 0
    total = len(args.models) * args.count

    reasoning_models = args.reasoning_models or [None] * len(args.models)
    if len(reasoning_models) == 1 and len(args.models) > 1:
        reasoning_models = reasoning_models * len(args.models)

    for i, model in enumerate(args.models):
        r_model = reasoning_models[i] if i < len(reasoning_models) else None
        print(f"\n{'=' * 60}")
        print(f"Model: {model} (Reasoning: {r_model or model})")
        print(f"{'=' * 60}")

        for _ in tqdm(range(args.count), desc=model):
            result = generate_site(
                client=client,
                coding_model=model,
                save_path=args.output,
                ctx=ctx,
                reasoning_model=r_model,
                country=args.country,
                language=args.language,
                temperature=args.temperature,
                agent_depth=args.agent_depth,
                vulnerability_presets=args.vulnerabilities,
            )
            if result:
                generated += 1
            else:
                failed += 1

    print(f"\n{'=' * 60}")
    print(f"Done! Generated: {generated}, Failed: {failed}, Total: {total}")
    print(f"Output: {args.output}")


def print_model_list(client) -> None:
    models = client.list_models()
    if models:
        print("Available models:")
        for model in models:
            print(f"  {model}")
    else:
        print("Could not retrieve model list from provider.")


def print_run_header(args, provider: str, base_url: str, context_name: str) -> None:
    print(f"[*] Context:      {context_name}")
    print(f"[*] Country:      {args.country or '(any)'}")
    print(f"[*] Language:     {args.language}")
    print(f"[*] Provider:     {provider}")
    print(f"[*] Base URL:     {base_url}")
    print(f"[*] Temperature:  {args.temperature}")
    print(f"[*] Agent depth:  {args.agent_depth}")
    print(f"[*] Vulnerabilities: {', '.join(args.vulnerabilities) if args.vulnerabilities else '(Randomly chosen)'}")
    print(f"[*] Models:       {', '.join(args.models)}")
    if args.reasoning_models:
        print(f"[*] Reasoning:    {', '.join(args.reasoning_models)}")


if __name__ == "__main__":
    main()
