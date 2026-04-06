"""Remediation patterns for common vulnerability types."""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class RemediationPattern:
    detection_regex: str
    principle: str
    fix_pattern: str


REMEDIATION_PATTERNS: dict[str, RemediationPattern] = {
    "hardcoded-credentials": RemediationPattern(
        detection_regex=r'(?i)(password|pwd|passwd|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
        principle="Never store secrets in source code. Use environment variables or a secrets manager.",
        fix_pattern="""
# BEFORE (vulnerable):
DB_PASSWORD = "admin123"

# AFTER (secure):
import os
DB_PASSWORD = os.environ.get("DB_PASSWORD")
if not DB_PASSWORD:
    raise RuntimeError("DB_PASSWORD environment variable is required")

# Even better - use a secrets manager:
# from azure.keyvault.secrets import SecretClient
# secret = client.get_secret("db-password")
""",
    ),
}
