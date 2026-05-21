"""Compatibility entrypoint for the heiLLMpot site generator."""

try:
    from sitegen.cli import main
    from sitegen.clients import (
        DEFAULT_BASE_URLS,
        DEFAULT_MODELS,
        OllamaClient,
        create_llm_client,
        normalize_provider,
    )
    from sitegen.context import DeploymentContext, build_context
    from sitegen.pipeline import generate_site
except ImportError:
    from generator.sitegen.cli import main
    from generator.sitegen.clients import (
        DEFAULT_BASE_URLS,
        DEFAULT_MODELS,
        OllamaClient,
        create_llm_client,
        normalize_provider,
    )
    from generator.sitegen.context import DeploymentContext, build_context
    from generator.sitegen.pipeline import generate_site


__all__ = [
    "DEFAULT_BASE_URLS",
    "DEFAULT_MODELS",
    "DeploymentContext",
    "OllamaClient",
    "build_context",
    "create_llm_client",
    "generate_site",
    "main",
    "normalize_provider",
]


if __name__ == "__main__":
    main()
