#!/usr/bin/env python3
"""Clean WHOIS provider implementation using new architecture."""

import shutil
import subprocess
from typing import Dict

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.celery_app import celery_app
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class WhoisProvider(BaseProvider):
    """Clean WHOIS provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "whois", config: Dict | None = None):
        """Initialize provider with WHOIS configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if WHOIS command is available (cross-platform)."""
        # Use shutil.which() which works on Windows, macOS, and Linux
        return shutil.which("whois") is not None

    def scan(self, target: str) -> ProviderResult:
        """Scan target with WHOIS lookup."""
        domain = self._extract_domain(target)

        try:
            # Run WHOIS command
            result = subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )

            if result.returncode != 0:
                return self._create_error_result(
                    target, f"WHOIS lookup failed: {result.stderr}"
                )

            return self._parse_whois_output(target, result.stdout)

        except subprocess.TimeoutExpired:
            return self._create_error_result(target, "WHOIS lookup timed out")
        except Exception as e:
            return self._create_error_result(target, f"WHOIS lookup error: {str(e)}")

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is."""
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            return urlparse(target).netloc
        return target

    def _parse_whois_output(self, target: str, whois_output: str) -> ProviderResult:
        """Parse WHOIS output into standard result."""
        from datetime import datetime, timezone

        output_lower = whois_output.lower()

        # Check for domain not found indicators
        not_found_indicators = [
            "no match",
            "not found",
            "no data found",
            "no entries found",
            "not resolve",
        ]

        if any(indicator in output_lower for indicator in not_found_indicators):
            return self._create_threat_result(
                target=target,
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence=0.9,
                details={
                    "status": "domain_not_found",
                    "raw_whois": whois_output[:1000],  # Truncate for storage
                },
            )

        # Parse creation date and other info
        creation_date_str = None
        registrar = None

        for line in whois_output.split("\n"):
            line_lower = line.lower()
            if (
                ("creation date" in line_lower)
                or ("created on" in line_lower)
                or (line_lower.startswith("created:"))
                or (line_lower.startswith("creation date:"))
                or ("domain registration date" in line_lower)
                or (line_lower.startswith("registered on"))
            ):
                # Take the part after colon if present, else the whole line
                parts = line.split(":", 1)
                creation_date_str = (parts[1] if len(parts) > 1 else line).strip()
            elif "registrar" in line_lower and "registrar url" not in line_lower:
                registrar = line.split(":", 1)[-1].strip()

        # Try to compute domain age days if we have a date string
        domain_age_days = None
        if creation_date_str:
            # Some WHOIS servers repeat dates or include timezone abbreviations; try multiple formats
            candidates = [
                p.strip() for p in creation_date_str.replace("\t", " ").split(",")
            ]
            # Common WHOIS date formats
            fmts = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
                "%d-%b-%Y %H:%M:%S %Z",
                "%Y.%m.%d %H:%M:%S",
                "%Y.%m.%d",
                "%Y/%m/%d",
                "%d.%m.%Y",
            ]

            created_dt = None
            for cand in candidates:
                for fmt in fmts:
                    try:
                        created_dt = datetime.strptime(cand, fmt)
                        # If naive, assume UTC
                        if created_dt.tzinfo is None:
                            created_dt = created_dt.replace(tzinfo=timezone.utc)
                        break
                    except Exception:
                        continue
                if created_dt:
                    break

            if created_dt:
                now = datetime.now(timezone.utc)
                delta = now - created_dt.astimezone(timezone.utc)
                # Ensure non-negative
                days = max(0, delta.days)
                domain_age_days = days

        # Domain exists and has valid registration
        details = {
            "status": "domain_found",
            "creation_date": creation_date_str,
            "registrar": registrar,
            "domain_age_days": domain_age_days,
            "raw_whois": whois_output[:1000],  # Truncate
        }

        return self._create_safe_result(target, details, confidence=0.8)


# Create Celery task
@celery_app.task(name="whois_scan")
def whois_scan(target: str, workflow_id: str = None) -> dict:
    """Celery task for WHOIS scanning."""
    with WhoisProvider() as provider:
        if workflow_id:
            provider.set_workflow_id(workflow_id)

        result = provider.scan_with_timing(target)

        # Return serializable result
        return {
            "provider": result.provider,
            "target": result.target,
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "details": result.details,
            "execution_time": result.execution_time,
            "error_message": result.error_message,
            "timestamp": result.timestamp.isoformat(),
        }
