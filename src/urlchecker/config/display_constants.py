#!/usr/bin/env python3
"""Display constants and formatting utilities."""

import os
import sys


class DisplayConstants:
    """Color codes and display formatting constants."""

    # ANSI color codes
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"

    # Colors
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYAN = "\x1b[36m"

    # Status indicators
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    HARMLESS = "HARMLESS"
    CLEAN = "CLEAN"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @staticmethod
    def should_use_color() -> bool:
        """Determine if colored output should be used."""
        return sys.stdout.isatty() and os.getenv("NO_COLOR") is None

    @staticmethod
    def format_with_color(text: str, color_code: str) -> str:
        """Apply color formatting if colors are enabled."""
        if DisplayConstants.should_use_color():
            return f"{color_code}{text}{DisplayConstants.RESET}"
        return text

    @classmethod
    def format_status(cls, status: str) -> str:
        """Format a status with appropriate color."""
        status_upper = status.upper()

        if status_upper == cls.MALICIOUS:
            return cls.format_with_color(status_upper, cls.BOLD + cls.RED)
        elif status_upper == cls.SUSPICIOUS:
            return cls.format_with_color(status_upper, cls.BOLD + cls.YELLOW)
        elif status_upper == cls.HARMLESS or status_upper == cls.CLEAN:
            return cls.format_with_color(status_upper, cls.BOLD + cls.GREEN)
        elif status_upper == cls.ERROR:
            return cls.format_with_color(status_upper, cls.BOLD + cls.YELLOW)
        else:
            return cls.format_with_color(status_upper, cls.BOLD + cls.CYAN)

    @classmethod
    def format_header(cls, text: str) -> str:
        """Format a header with bold cyan."""
        return cls.format_with_color(text, cls.BOLD + cls.CYAN)

    @classmethod
    def format_warning(cls, text: str) -> str:
        """Format warning text."""
        return cls.format_with_color(f"[WARN] {text}", cls.YELLOW)

    @classmethod
    def format_error(cls, text: str) -> str:
        """Format error text."""
        return cls.format_with_color(f"[ERROR] {text}", cls.RED)

    @classmethod
    def format_info(cls, text: str) -> str:
        """Format info text."""
        return cls.format_with_color(f"[INFO] {text}", cls.CYAN)

    @staticmethod
    def sanitize_url_for_display(url: str) -> str:
        """Make URLs safe for display by breaking automatic linking."""
        if not url:
            return url

        # Replace protocols
        url = url.replace("https://", "https[:]//")
        url = url.replace("http://", "http[:]//")

        # Replace common prefixes
        url = url.replace("www.", "www[.]")

        return url
