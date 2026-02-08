"""
AI Provider Abstraction Layer

Supports both direct Anthropic API (via CLAUDE_API_KEY) and AWS Bedrock.

Usage:
    from lib.ai_provider import create_client

    client = create_client()               # auto-detect from env
    client = create_client("anthropic")    # force direct API
    client = create_client("bedrock")      # force Bedrock

Environment variables:
    AGENTSMITH_PROVIDER  - "anthropic" (default) or "bedrock"
    CLAUDE_API_KEY       - Required when provider is "anthropic"
    AWS_REGION           - AWS region for Bedrock (default: us-east-1)
    AWS_PROFILE          - Optional AWS profile name for Bedrock
"""

import logging
import os
import sys

logger = logging.getLogger(__name__)

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_BEDROCK = "bedrock"
VALID_PROVIDERS = {PROVIDER_ANTHROPIC, PROVIDER_BEDROCK}


def get_provider() -> str:
    """Return the configured AI provider name."""
    provider = os.getenv("AGENTSMITH_PROVIDER", PROVIDER_ANTHROPIC).lower().strip()
    if provider not in VALID_PROVIDERS:
        logger.warning(f"Unknown provider '{provider}', falling back to 'anthropic'")
        return PROVIDER_ANTHROPIC
    return provider


def create_client(provider: str = None):
    """
    Factory that returns an Anthropic-compatible client.

    Both clients expose the same `client.messages.create()` interface,
    so all downstream code works identically regardless of provider.

    Args:
        provider: "anthropic" or "bedrock". If None, reads from
                  AGENTSMITH_PROVIDER env var (default: "anthropic").

    Returns:
        anthropic.Anthropic or anthropic.AnthropicBedrock instance.

    Raises:
        SystemExit: If required credentials are missing.
    """
    import anthropic

    provider = provider or get_provider()

    if provider == PROVIDER_BEDROCK:
        try:
            from anthropic import AnthropicBedrock
        except ImportError:
            logger.error(
                "Bedrock support requires the 'anthropic[bedrock]' extra. "
                "Install with: pip install 'anthropic[bedrock]'"
            )
            sys.exit(1)

        region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
        logger.info(f"Using AWS Bedrock provider (region={region})")
        return AnthropicBedrock(aws_region=region)

    # Default: direct Anthropic API
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        logger.error("CLAUDE_API_KEY environment variable not set.")
        sys.exit(1)

    logger.info("Using Anthropic API provider")
    return anthropic.Anthropic(api_key=api_key)
