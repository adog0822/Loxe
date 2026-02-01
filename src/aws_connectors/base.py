"""Base AWS connector with shared session management."""

from __future__ import annotations

import os
from functools import lru_cache

import boto3
from botocore.config import Config


@lru_cache(maxsize=1)
def get_session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )


_RETRY_CONFIG = Config(retries={"max_attempts": 3, "mode": "adaptive"})


class BaseConnector:
    """Base class for all AWS service connectors."""

    service_name: str = ""

    def __init__(self) -> None:
        session = get_session()
        self.client = session.client(self.service_name, config=_RETRY_CONFIG)

    def paginate(self, method: str, key: str, **kwargs) -> list:
        """Generic paginator helper that collects all pages into a list."""
        paginator = self.client.get_paginator(method)
        results: list = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(key, []))
        return results
