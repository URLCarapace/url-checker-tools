#!/usr/bin/env python3
"""Simplified exception classes for the URL checker."""


class URLCheckerError(Exception):
    """Base exception for URL checker."""

    pass


class MissingAPIKeyError(URLCheckerError):
    """Raised when a required API key is not found."""

    pass


class APIRequestError(URLCheckerError):
    """Raised when an API request fails."""

    pass


class APIResponseError(URLCheckerError):
    """Raised when an API returns invalid data."""

    pass


class YaraNotAvailableError(URLCheckerError):
    """Raised when YARA scanning is requested but not available."""

    pass


class ConfigurationError(URLCheckerError):
    """Raised when there's a configuration issue."""

    pass


class WhoisNotFoundError(URLCheckerError):
    """Raised when domain is not found in WHOIS database."""

    pass


class WhoisTimeoutError(URLCheckerError):
    """Raised when WHOIS lookup times out."""

    pass


class DNSBlockedException(URLCheckerError):
    """Raised when a DNS/corporate block page is detected."""

    pass
