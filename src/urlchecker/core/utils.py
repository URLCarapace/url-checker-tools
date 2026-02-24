#!/usr/bin/env python3
"""Simplified utility functions."""
from typing import List, Optional
from urllib.parse import urlparse


class ConfigDict:
    """Simple wrapper to provide attribute access to dictionary config."""

    def __init__(self, config_dict: dict):
        self._config = config_dict

    def __getattr__(self, name):
        if name in self._config:
            return self._config[name]
        # Provide defaults for common attributes
        defaults = {
            "rate_limit_per_minute": 60,
            "timeout": 30,
            "max_retries": 3,
            "verbose": False,
        }
        return defaults.get(name, None)


def is_full_url(target: str) -> bool:
    """Check if the target is a full URL (starts with http:// or https://)."""
    if not target:
        return False

    target_lower = target.strip().lower()
    return target_lower.startswith(("http://", "https://"))


def validate_target(target: str) -> str:
    """Validate and normalize a scan target."""
    import re

    if not target or not target.strip():
        raise ValueError("Target cannot be empty")

    target = target.strip()

    # Enhanced security validation for URLs and domains
    if is_full_url(target):
        # URL validation
        if not re.match(r"^https?://[a-zA-Z0-9.-]+(/[^\s]*)?$", target):
            # Allow more flexible URL patterns but block dangerous characters
            dangerous_chars = [";", "&", "|", "`", "$", '"', "'"]
            if any(char in target for char in dangerous_chars):
                raise ValueError(f"URL contains unsafe characters: {target}")
    else:
        # Domain validation (similar to WHOIS scanner)
        if not re.match(r"^[a-zA-Z0-9.-]+$", target):
            raise ValueError(f"Invalid domain format: {target}")

        dangerous_chars = [
            ";",
            "&",
            "|",
            "`",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            "<",
            ">",
            '"',
            "'",
        ]
        if any(char in target for char in dangerous_chars):
            raise ValueError(f"Target contains unsafe characters: {target}")

    # Length validation
    if len(target) > 2048:  # Reasonable URL length limit
        raise ValueError(f"Target too long: {len(target)} characters")

    return target


def prompt_for_file_scanning(download_urls: List[str]) -> Optional[List[str]]:
    """
    Prompt user to select which download URLs to scan.

    Args:
        download_urls: List of detected download URLs

    Returns:
        List of selected URLs to scan
    """
    if not download_urls:
        return []

    print(f"\nDetected {len(download_urls)} download link(s):")
    print("=" * 50)

    for i, url in enumerate(download_urls, 1):
        parsed = urlparse(url)
        filename = parsed.path.split("/")[-1] if parsed.path else parsed.netloc
        display = url if len(url) <= 70 else f"{filename} ({url[:30]}...{url[-15:]})"
        print(f"  {i}. {display}")

    print("\nOptions: A=all, N=no (skip), or numbers separated by commas (1,2,3): ")

    try:
        response = input("Your choice: ").strip().lower()

        if response in ("a", "all"):
            print(f"[OK] Scanning all {len(download_urls)} files...")
            return download_urls

        if response in ("n", "no", "none", ""):
            print("Skipping file scanning")
            return []

        # Simple number processing - just split and validate
        try:
            numbers = [int(x.strip()) for x in response.split(",") if x.strip()]
            valid_numbers = [n for n in numbers if 1 <= n <= len(download_urls)]

            if valid_numbers:
                selected = [download_urls[n - 1] for n in valid_numbers]
                # Remove duplicates
                unique = list(dict.fromkeys(selected))
                print(f"[OK] Scanning {len(unique)} selected file(s)...")
                return unique
            else:
                print("No valid files selected, skipping file scanning")
                return []

        except ValueError:
            print("[ERROR] Invalid input. Skipping file scanning")
            return []

    except (KeyboardInterrupt, EOFError):
        print("\nFile scanning cancelled by user")
        return []
