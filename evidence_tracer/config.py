"""Configuration management for Evidence Tracer."""

import os
from pathlib import Path


class Config:
    """Application configuration loaded from environment or defaults."""

    def __init__(self):
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.max_search_results = int(os.getenv("MAX_SEARCH_RESULTS", "5"))
        self.search_timeout = int(os.getenv("SEARCH_TIMEOUT", "10"))
        self.output_dir = Path(os.getenv("OUTPUT_DIR", "./output"))
        self.default_format = os.getenv("DEFAULT_FORMAT", "markdown")

    @property
    def has_ai_key(self) -> bool:
        return bool(self.anthropic_api_key or self.openai_api_key)

    def ensure_output_dir(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
