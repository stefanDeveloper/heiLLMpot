"""
OllamaClient — wrapper for the official ollama python library.
"""

from __future__ import annotations

import os
import random
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from ollama import Client

# Load .env from project root
load_dotenv(Path(__file__).parent.parent / ".env")


class OllamaClient:
    """Thin client for Ollama using the official library.

    The API key is read from OLLAMA_API_KEY environment variable.
    The base URL is read from OLLAMA_BASE_URL (defaults to http://localhost:11434).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: int = 300,
        max_retries: int = 3,
        api_key: Optional[str] = None,
    ):
        # Priority: constructor arg > env var > default
        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL")
            or "http://localhost:11434"
        )
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY")
        self.timeout = timeout
        self.max_retries = max_retries

        # Initialize official client
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        self._client = Client(
            host=self.base_url,
            headers=headers,
            timeout=self.timeout,
        )

    def generate(
        self, prompt: str, model: str, temperature: float = 0.3
    ) -> str:
        """Call Ollama generate or chat API and return response text."""
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            try:
                # We use chat API as it is more robust for modern cloud models
                response = self._client.chat(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    options={"temperature": temperature},
                )
                return response.message.content
            except Exception as e:
                last_error = e
                # Check for common retryable errors
                wait = 2**attempt + random.uniform(0, 1)
                print(
                    f"    [retry {attempt + 1}/{self.max_retries}] "
                    f"Error: {e}. Retrying in {wait:.1f}s..."
                )
                time.sleep(wait)

        raise RuntimeError(
            f"Ollama request failed after {self.max_retries} retries: {last_error}"
        )

    def list_models(self) -> list[str]:
        """Return list of available model names."""
        try:
            response = self._client.list()
            return [m.model for m in response.models]
        except Exception:
            return []
