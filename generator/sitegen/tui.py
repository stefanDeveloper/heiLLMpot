"""Curses-based interactive configuration UI for the site generator."""

from __future__ import annotations

import argparse
import curses
import locale
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from .clients import (
    API_KEY_ENV_VARS,
    DEFAULT_BASE_URLS,
    DEFAULT_MODELS,
    PROVIDER_ALIASES,
    normalize_provider,
)


@dataclass
class Field:
    key: str
    label: str
    kind: str = "text"
    options: list[str] | None = None
    secret: bool = False
    help_text: str = ""


ICONS = {
    "title": ("✦", "*"),
    "provider": ("◈", "#"),
    "model": ("◆", "*"),
    "context": ("▣", "[ ]"),
    "agent": ("⚙", "@"),
    "run": ("▶", ">"),
    "ok": ("✓", "+"),
    "warn": ("!", "!"),
    "arrow": ("➜", "->"),
}


def run_interactive(args: argparse.Namespace) -> argparse.Namespace | None:
    """Launch the terminal UI and return updated args, or None on cancel."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("[!] --interactive requires a real terminal (TTY).", file=sys.stderr)
        return None

    locale.setlocale(locale.LC_ALL, "")
    state = state_from_args(args)

    too_small: list[bool] = []

    def _run(stdscr):
        result = Tui(stdscr, state).run()
        if result is None and getattr(_run, "_too_small", False):
            too_small.append(True)
        return result

    try:
        result = curses.wrapper(lambda stdscr: Tui(stdscr, state, too_small).run())
    except KeyboardInterrupt:
        print("Cancelled via Ctrl-C.", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[!] TUI error: {exc}", file=sys.stderr)
        return None

    if too_small:
        print("[!] Terminal too small. Please resize to at least 80×24 and retry.",
              file=sys.stderr)
        return None

    if result is None:
        print("Cancelled.", file=sys.stderr)
        return None

    apply_state_to_args(args, result)
    return args


def state_from_args(args: argparse.Namespace) -> dict[str, str]:
    raw_provider = normalize_provider(args.provider)
    if raw_provider == "ollama":
        url = args.ollama_url or os.environ.get("OLLAMA_BASE_URL", "")
        # If URL points to cloud domain, or if we have an API key set, default to ollama-cloud
        if "api.ollama.cloud" in url or "ollama.com" in url or args.api_key or os.environ.get("OLLAMA_API_KEY"):
            provider = "ollama-cloud"
        else:
            provider = "ollama-local"
    else:
        provider = raw_provider

    # Resolve default model if none specified
    if args.models:
        models = " ".join(args.models)
    else:
        if provider == "ollama-local":
            models = "llama3.2:3b"
        elif provider == "ollama-cloud":
            models = "gemma4"
        else:
            models = DEFAULT_MODELS.get(raw_provider, "")

    return {
        "provider": provider,
        "models": models,
        "context": args.context,
        "country": args.country,
        "language": args.language,
        "count": str(args.count),
        "agent_depth": args.agent_depth,
        "output": args.output,
        "temperature": str(args.temperature),
        "max_output_tokens": str(args.max_output_tokens),
        "ollama_url": args.ollama_url or "",
        "api_base_url": args.api_base_url or "",
        "api_key": args.api_key or "",
        "vulnerability": args.vulnerability or "",
    }


def apply_state_to_args(args: argparse.Namespace, state: dict[str, str]) -> None:
    raw_prov = state["provider"]
    if raw_prov.startswith("ollama"):
        provider = "ollama"
    else:
        provider = normalize_provider(raw_prov)
    args.provider = provider
    args.models = split_models(state["models"]) or [DEFAULT_MODELS[provider]]
    args.context = state["context"]
    args.country = state["country"]
    args.language = state["language"] or "English"
    args.count = parse_int(state["count"], args.count)
    args.agent_depth = state["agent_depth"]
    args.output = state["output"] or "./generated_sites"
    args.temperature = parse_float(state["temperature"], args.temperature)
    args.max_output_tokens = parse_int(
        state["max_output_tokens"],
        args.max_output_tokens,
    )
    args.ollama_url = state["ollama_url"] or DEFAULT_BASE_URLS["ollama"]
    args.api_base_url = state["api_base_url"]
    args.api_key = state["api_key"]
    args.vulnerability = state.get("vulnerability") or None


def split_models(value: str) -> list[str]:
    return [part.strip() for part in value.replace(",", " ").split() if part.strip()]


def parse_int(value: str, fallback: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else fallback
    except ValueError:
        return fallback


def parse_float(value: str, fallback: float) -> float:
    try:
        return float(value)
    except ValueError:
        return fallback


class Tui:
    def __init__(self, stdscr, state: dict[str, str],
                 too_small_flag: list | None = None):
        self.stdscr = stdscr
        self.state = state
        self.too_small_flag = too_small_flag
        self.cursor = 0
        self.message = "↑↓ navigate · Enter/←→ edit · s=start · q=quit"
        self.unicode = terminal_supports_unicode()
        self.contexts = self.load_contexts()
        self.vuln_presets = self.load_vuln_presets()
        self.fields = self.build_fields()

        if not self.state.get("vulnerability") and self.vuln_presets:
            self.state["vulnerability"] = self.vuln_presets[0]

        if not self.state.get("provider"):
            self.state["provider"] = "ollama-local"

    def run(self) -> dict[str, str] | None:
        curses.curs_set(0)
        self.stdscr.keypad(True)
        curses.use_default_colors()
        self.init_colors()

        while True:
            self.render()
            key = self.stdscr.getch()
            if key in (ord("q"), 27):
                return None
            if key in (ord("s"), curses.KEY_F10):
                return self.state
            if key in (curses.KEY_UP, ord("k")):
                self.cursor = (self.cursor - 1) % len(self.fields)
            elif key in (curses.KEY_DOWN, ord("j"), ord("\t")):
                self.cursor = (self.cursor + 1) % len(self.fields)
            elif key in (curses.KEY_LEFT, ord("h")):
                self.cycle_current(-1)
            elif key in (curses.KEY_RIGHT, ord("l"), ord(" ")):
                self.cycle_current(1)
            elif key in (curses.KEY_ENTER, 10, 13):
                self.activate_current()

    def init_colors(self) -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)


    def load_contexts(self) -> list[str]:
        contexts_dir = Path(__file__).resolve().parents[1] / "contexts"
        contexts = sorted(path.stem for path in contexts_dir.glob("*.json"))
        aliases = ["ai-company", "llm-provider", "model-provider"]
        return sorted(set(contexts + aliases))

    def load_vuln_presets(self) -> list[str]:
        vuln_dir = Path(__file__).resolve().parents[1] / "vulnerabilities"
        presets = sorted(path.stem for path in vuln_dir.glob("*.json"))
        return presets + [""]  # First preset becomes default

    def get_models_for_provider(self, provider: str) -> list[str]:
        if provider == "ollama-local":
            return ["llama3.2:3b", "llama3:8b", "llama3:70b", "mistral", "gemma2"]
        elif provider == "ollama-cloud":
            return [
                "gemma4",
                "qwen3.5",
                "gemma3",
                "deepseek-v4-pro",
                "gpt-oss",
                "mistral-large-3",
                "glm-5",
                "minimax-m2.7",
                "qwen3-coder-next",
                "devstral-small-2"
            ]
        elif provider == "openai":
            return ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]
        elif provider == "anthropic":
            return ["claude-3-5-sonnet", "claude-3-opus", "claude-3-haiku"]
        elif provider == "google":
            return ["gemini-2.5-flash", "gemini-2.0-pro"]
        return ["default"]

    def build_fields(self) -> list[Field]:
        return [
            Field(
                "provider", "Provider", "choice",
                ["ollama-local", "ollama-cloud", "openai", "anthropic", "google"],
                help_text="Cloud providers use API keys from env vars or the API Key field.",
            ),
            Field(
                "models", "Model", "choice",
                self.get_models_for_provider(self.state.get("provider", "ollama-local")),
                help_text="Select a model for the current provider (cycle with arrows).",
            ),
            Field(
                "context", "Context", "choice", self.contexts,
                help_text="Use ai_company/ai-company for AI vendor-style portals.",
            ),
            Field(
                "vulnerability", "Vulnerability", "choice", self.vuln_presets,
                help_text="Preset to enforce. Empty = LLM chooses freely.",
            ),
            Field("country", "Country",
                  help_text="ISO code, e.g. US or DE. Empty lets the LLM choose."),
            Field("language", "Language"),
            Field("count", "Sites",
                  help_text="How many sites to generate per model."),
            Field(
                "agent_depth", "Agent Depth", "choice",
                ["basic", "standard", "deep"],
                help_text="Deep adds final realism QA for more polished pages.",
            ),
            Field("output", "Output Dir"),
            Field("temperature", "Temperature"),
            Field("max_output_tokens", "Max Tokens"),
            Field("ollama_url", "Ollama URL"),
            Field("api_base_url", "API Base URL",
                  help_text="Optional hosted-provider override."),
            Field("api_key", "API Key", secret=True,
                  help_text="Optional; env vars are preferred."),
        ]

    def render(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 24 or width < 80:
            msg = f"Terminal too small ({width}x{height}). Need at least 80x24."
            self.stdscr.addnstr(0, 0, msg, width)
            self.stdscr.refresh()
            if self.too_small_flag is not None and not self.too_small_flag:
                self.too_small_flag.append(True)
            return

        self.draw_frame(height, width)
        self.draw_header(width)
        self.draw_fields(width)
        self.draw_preview(height, width)
        self.draw_footer(height, width)
        self.stdscr.refresh()

    def draw_frame(self, height: int, width: int) -> None:
        self.stdscr.border()
        for y in range(2, height - 2):
            self.add(y, 42, "│" if self.unicode else "|", curses.color_pair(1))

    def draw_header(self, width: int) -> None:
        title = f"{self.icon('title')} heiLLMpot Site Generator"
        subtitle = "interactive terminal control panel"
        self.add(1, 3, title, curses.A_BOLD | curses.color_pair(1))
        self.add(1, max(3, width - len(subtitle) - 4), subtitle, curses.color_pair(4))

    def draw_fields(self, width: int) -> None:
        self.add(3, 3, f"{self.icon('provider')} Configuration", curses.A_BOLD)
        for index, field in enumerate(self.fields):
            y = 5 + index
            attr = curses.color_pair(2) if index == self.cursor else curses.A_NORMAL
            label = f"{field.label:14}"
            value = self.display_value(field)
            row = f" {self.icon('arrow') if index == self.cursor else '  '} {label} {value}"
            self.add(y, 3, row[:37], attr)

        selected = self.fields[self.cursor]
        self.add(20, 3, selected.help_text[:36], curses.color_pair(4))
        key_hint = "↔ cycle  Enter edit" if selected.kind == "choice" else "Enter edit"
        self.add(21, 3, key_hint if self.unicode else key_hint.replace("↔", "<>"))

    def draw_preview(self, height: int, width: int) -> None:
        x = 45
        self.add(3, x, f"{self.icon('run')} Run Preview", curses.A_BOLD)
        lines = command_preview(self.state)
        for offset, line in enumerate(lines[:height - 9]):
            self.add(5 + offset, x, line[:width - x - 3])

        warnings = config_warnings(self.state)
        y = height - 7
        self.add(y, x, f"{self.icon('warn')} Checks", curses.A_BOLD | curses.color_pair(4))
        if warnings:
            for offset, warning in enumerate(warnings[:3]):
                self.add(y + 1 + offset, x, warning[:width - x - 3], curses.color_pair(4))
        else:
            self.add(y + 1, x, f"{self.icon('ok')} Looks ready", curses.color_pair(3))

    def draw_footer(self, height: int, width: int) -> None:
        footer = f" {self.message} "
        self.add(height - 2, 2, footer[:width - 4], curses.color_pair(1))

    def cycle_current(self, direction: int) -> None:
        field = self.fields[self.cursor]
        if field.kind != "choice" or not field.options:
            return
        current = self.state.get(field.key, "")
        try:
            index = field.options.index(current)
        except ValueError:
            index = 0
        self.state[field.key] = field.options[(index + direction) % len(field.options)]
        if field.key == "provider":
            prov_choice = self.state[field.key]
            model_field = next(f for f in self.fields if f.key == "models")
            model_field.options = self.get_models_for_provider(prov_choice)
            self.state["models"] = model_field.options[0]
            
            if prov_choice == "ollama-local":
                self.state["ollama_url"] = "http://localhost:11434"
                self.state["api_key"] = ""
            elif prov_choice == "ollama-cloud":
                self.state["ollama_url"] = os.environ.get("OLLAMA_BASE_URL", "https://api.ollama.cloud")
                self.state["api_key"] = os.environ.get("OLLAMA_API_KEY", "")
            else:
                if not self.state.get("api_base_url"):
                    self.state["api_base_url"] = ""

    def activate_current(self) -> None:
        field = self.fields[self.cursor]
        value = self.state.get(field.key, "")
        prompt = f"{field.label}: "
        new_value = self.prompt_text(prompt, value, secret=field.secret)
        if new_value is not None:
            self.state[field.key] = new_value
            if field.key == "provider":
                prov_choice = self.state[field.key]
                model_field = next((f for f in self.fields if f.key == "models"), None)
                if model_field:
                    model_field.options = self.get_models_for_provider(prov_choice)
                    if model_field.options:
                        self.state["models"] = model_field.options[0]

    def prompt_text(self, prompt: str, initial: str, secret: bool = False) -> str | None:
        height, width = self.stdscr.getmaxyx()
        y = height - 4
        curses.echo()
        curses.curs_set(1)
        self.add(y, 2, " " * (width - 4))
        self.add(y, 3, prompt)
        x = 3 + len(prompt)
        current = "*" * 8 if secret and initial else initial
        if current:
            hint = f"(current: {current[:max(0, width - x - 18)]}) "
            self.add(y, x, hint)
            x += len(hint)
        self.stdscr.move(y, x)
        self.stdscr.refresh()

        if secret:
            curses.noecho()
        
        # Discard any leftover newline keys in the input buffer
        curses.flushinp()
        try:
            raw = self.stdscr.getstr(y, x, width - x - 4)
        finally:
            curses.noecho()
            curses.curs_set(0)

        try:
            value = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            value = raw.decode(errors="ignore").strip()
        if value == "-":
            return ""
        return value or initial

    def display_value(self, field: Field) -> str:
        value = self.state.get(field.key, "")
        if field.secret and value:
            return "*" * 8
        if field.kind == "choice":
            return f"< {value} >"
        return value or "(empty)"

    def icon(self, key: str) -> str:
        return ICONS[key][0 if self.unicode else 1]

    def add(self, y: int, x: int, text: str, attr: int = 0) -> None:
        try:
            self.stdscr.addnstr(y, x, text, max(0, self.stdscr.getmaxyx()[1] - x - 1), attr)
        except curses.error:
            pass


def terminal_supports_unicode() -> bool:
    encoding = locale.getpreferredencoding(False).lower()
    return "utf" in encoding


def command_preview(state: dict[str, str]) -> list[str]:
    raw_prov = state.get("provider", "ollama-local")
    provider = "ollama" if raw_prov.startswith("ollama") else normalize_provider(raw_prov)
    parts = [
        "python3 -m generator.sitegen.cli",
        "--provider", provider,
        "--models", state.get("models") or DEFAULT_MODELS[provider],
        "--context", state.get("context", "university"),
        "--count", state.get("count", "1"),
        "--agent-depth", state.get("agent_depth", "standard"),
        "--output", state.get("output", "./generated_sites"),
    ]

    optional_pairs = [
        ("--country", state.get("country", "")),
        ("--language", state.get("language", "")),
        ("--temperature", state.get("temperature", "")),
        ("--max-output-tokens", state.get("max_output_tokens", "")),
    ]
    for flag, value in optional_pairs:
        if value:
            parts.extend([flag, value])

    if provider == "ollama" and state.get("ollama_url"):
        parts.extend(["--ollama-url", state["ollama_url"]])
    elif provider != "ollama" and state.get("api_base_url"):
        parts.extend(["--api-base-url", state["api_base_url"]])
    if state.get("api_key"):
        parts.extend(["--api-key", "<provided>"])

    command = " ".join(shlex.quote(part) for part in parts)
    return wrap_text(command, 58)


def config_warnings(state: dict[str, str]) -> list[str]:
    warnings = []
    raw_prov = state.get("provider", "ollama-local")
    provider = "ollama" if raw_prov.startswith("ollama") else normalize_provider(raw_prov)
    
    if raw_prov == "ollama-cloud":
        if not state.get("api_key") and not os.environ.get("OLLAMA_API_KEY"):
            warnings.append("Ollama Cloud typically requires an API key.")
    elif provider != "ollama" and not state.get("api_key"):
        env_names = API_KEY_ENV_VARS.get(provider, [])
        if not any(os.getenv(name) for name in env_names):
            warnings.append(f"No API key found for {provider}.")
    if not split_models(state.get("models", "")):
        warnings.append("No model set; provider default will be used.")
    if parse_int(state.get("count", "0"), 0) <= 0:
        warnings.append("Count is 0; no sites will be generated.")
    return warnings


def split_models(value: str) -> list[str]:
    return [part.strip() for part in value.replace(",", " ").split() if part.strip()]


def wrap_text(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]
