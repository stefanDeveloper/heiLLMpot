"""LLM provider clients used by the site generator."""

from __future__ import annotations

import os
import random
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests
from dotenv import load_dotenv

# Load .env from project root (two levels up from this file)
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class OllamaClient:
    """Ollama client using the official `ollama` Python library.

    Supports both local Ollama and cloud/hosted Ollama instances.
    Configuration (in order of priority):
      - Constructor args (base_url, api_key)
      - Environment variables: OLLAMA_BASE_URL, OLLAMA_API_KEY
      - Defaults: http://localhost:11434, no key
    """

    def __init__(self, base_url: str = "",
                 timeout: int = 300, max_retries: int = 3,
                 max_output_tokens: int = 8192,
                 api_key: str = ""):
        from ollama import Client as _OllamaLibClient

        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        ).rstrip("/")
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_output_tokens = max_output_tokens

        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        self._client = _OllamaLibClient(
            host=self.base_url,
            headers=headers,
            timeout=self.timeout,
        )

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        """Call Ollama chat API and return response text, with retries."""
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                import concurrent.futures
                
                def _do_stream():
                    stream = self._client.chat(
                        model=model,
                        messages=[{"role": "user", "content": prompt}],
                        options={"temperature": temperature,
                                 "num_ctx": 16384,
                                 "num_predict": self.max_output_tokens},
                        stream=True,
                    )
                    chunks = []
                    for chunk in stream:
                        chunks.append(chunk.message.content)
                    return "".join(chunks)

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_do_stream)
                    try:
                        result = future.result(timeout=self.timeout)
                        if not result or not result.strip():
                            raise RuntimeError("Ollama returned an empty/whitespace response")
                        return result
                    except concurrent.futures.TimeoutError:
                        raise TimeoutError(f"Ollama stream read timed out after {self.timeout}s")
            except Exception as e:
                last_error = e
                wait = 2 ** attempt + random.uniform(0, 1)
                print(f"    [retry {attempt + 1}/{self.max_retries}] "
                      f"Error: {e}. Retrying in {wait:.1f}s...")
                time.sleep(wait)
        raise RuntimeError(
            f"Ollama request failed after {self.max_retries} retries: "
            f"{last_error}"
        )

    def list_models(self) -> list[str]:
        try:
            response = self._client.list()
            return [m.model for m in response.models]
        except Exception:
            return []


class HostedLLMClient:
    """Base class for hosted text-generation APIs."""

    provider = "hosted"

    def __init__(self, base_url: str, api_key: str, timeout: int = 300,
                 max_retries: int = 3, max_output_tokens: int = 8192):
        if not api_key:
            raise ValueError(f"Missing API key for provider '{self.provider}'")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_output_tokens = max_output_tokens

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        raise NotImplementedError

    def list_models(self) -> list[str]:
        return []

    def _post_json(self, url: str, payload: dict, headers: dict) -> dict:
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                res = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
                res.raise_for_status()
                return res.json()
            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = e
                wait = 2 ** attempt + random.uniform(0, 1)
                print(f"    [retry {attempt + 1}/{self.max_retries}] "
                      f"Connection error: {e}. Retrying in {wait:.1f}s...")
                time.sleep(wait)
            except requests.HTTPError:
                raise
        raise RuntimeError(
            f"{self.provider} request failed after "
            f"{self.max_retries} retries: {last_error}"
        )


class OpenAIClient(HostedLLMClient):
    """OpenAI Responses API client."""

    provider = "openai"

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        payload = {
            "model": model,
            "input": prompt,
            "temperature": temperature,
            "max_output_tokens": self.max_output_tokens,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        data = self._post_json(f"{self.base_url}/responses", payload, headers)
        if isinstance(data.get("output_text"), str):
            return data["output_text"]

        chunks: list[str] = []
        for item in data.get("output", []):
            for content in item.get("content", []):
                text = content.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        if chunks:
            return "".join(chunks)
        raise RuntimeError("OpenAI response did not contain text output")

    def list_models(self) -> list[str]:
        try:
            res = requests.get(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=10,
            )
            res.raise_for_status()
            return [m["id"] for m in res.json().get("data", [])]
        except Exception:
            return []


class AnthropicClient(HostedLLMClient):
    """Anthropic Messages API client."""

    provider = "anthropic"

    @property
    def messages_url(self) -> str:
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/messages"
        return f"{self.base_url}/v1/messages"

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        payload = {
            "model": model,
            "max_tokens": self.max_output_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        data = self._post_json(self.messages_url, payload, headers)
        chunks = [
            part["text"]
            for part in data.get("content", [])
            if part.get("type") == "text" and isinstance(part.get("text"), str)
        ]
        if chunks:
            return "".join(chunks)
        raise RuntimeError("Anthropic response did not contain text output")


class GoogleClient(HostedLLMClient):
    """Google Gemini generateContent API client."""

    provider = "google"

    def generate(self, prompt: str, model: str,
                 temperature: float = 0.3) -> str:
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }
        headers = {"Content-Type": "application/json"}
        model_path = model if model.startswith("models/") else f"models/{model}"
        url = (
            f"{self.base_url}/{model_path}:generateContent"
            f"?key={quote(self.api_key)}"
        )
        data = self._post_json(url, payload, headers)
        chunks: list[str] = []
        for candidate in data.get("candidates", []):
            for part in candidate.get("content", {}).get("parts", []):
                text = part.get("text")
                if isinstance(text, str):
                    chunks.append(text)
        if chunks:
            return "".join(chunks)
        raise RuntimeError("Google response did not contain text output")

    def list_models(self) -> list[str]:
        try:
            res = requests.get(
                f"{self.base_url}/models?key={quote(self.api_key)}",
                timeout=10,
            )
            res.raise_for_status()
            return [
                m.get("name", "").replace("models/", "")
                for m in res.json().get("models", [])
                if m.get("name")
            ]
        except Exception:
            return []


PROVIDER_ALIASES = {
    "ollama": "ollama",
    "local": "ollama",
    "openai": "openai",
    "oai": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "google": "google",
    "gemini": "google",
}

DEFAULT_BASE_URLS = {
    # For Ollama: prefer OLLAMA_BASE_URL env var (set in .env for cloud)
    "ollama": os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com/v1beta",
}

DEFAULT_MODELS = {
    "ollama": "llama3.2:3b",
    "openai": "gpt-5-mini",
    "anthropic": "claude-sonnet-4-5",
    "google": "gemini-2.5-flash",
}

API_KEY_ENV_VARS = {
    "openai": ["OPENAI_API_KEY"],
    "anthropic": ["ANTHROPIC_API_KEY"],
    "google": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
}


def normalize_provider(provider: str) -> str:
    key = provider.strip().lower()
    if key not in PROVIDER_ALIASES:
        raise ValueError(
            f"Unknown provider '{provider}'. Available: "
            f"{sorted(set(PROVIDER_ALIASES.values()))}"
        )
    return PROVIDER_ALIASES[key]


def resolve_api_key(provider: str, explicit_key: str = "") -> str:
    if explicit_key:
        return explicit_key
    for env_name in API_KEY_ENV_VARS.get(provider, []):
        value = os.getenv(env_name)
        if value:
            return value
    return ""


def create_llm_client(provider: str, base_url: str = "",
                      api_key: str = "", timeout: int = 300,
                      max_retries: int = 3,
                      max_output_tokens: int = 8192):
    provider = normalize_provider(provider)
    base_url = (base_url or DEFAULT_BASE_URLS[provider]).rstrip("/")

    if provider == "ollama":
        return OllamaClient(
            base_url=base_url,
            api_key=api_key or os.environ.get("OLLAMA_API_KEY", ""),
            timeout=timeout,
            max_retries=max_retries,
            max_output_tokens=max_output_tokens,
        )

    resolved_key = resolve_api_key(provider, api_key)
    if provider == "openai":
        return OpenAIClient(base_url, resolved_key, timeout,
                            max_retries, max_output_tokens)
    if provider == "anthropic":
        return AnthropicClient(base_url, resolved_key, timeout,
                               max_retries, max_output_tokens)
    if provider == "google":
        return GoogleClient(base_url, resolved_key, timeout,
                            max_retries, max_output_tokens)

    raise ValueError(f"Unsupported provider: {provider}")
