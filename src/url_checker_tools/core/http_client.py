#!/usr/bin/env python3
"""Unified HTTP client with provider-aware features."""

import json
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from .utils import ConfigDict


class RateLimiter:
    """Simple rate limiter for HTTP requests.

    Supports either a per-minute cap or a fixed minimum delay between calls.
    """

    def __init__(self, calls_per_minute: int, delay_seconds: Optional[float] = None):
        self.calls_per_minute = calls_per_minute
        self.delay_seconds = delay_seconds
        self.calls = []

    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        now = time.time()

        # If using fixed delay mode, ensure a minimum delay between calls
        if self.delay_seconds is not None and self.calls:
            elapsed = now - self.calls[-1]
            if elapsed < self.delay_seconds:
                time.sleep(self.delay_seconds - elapsed)
            # Record this call time after sleeping
            now = time.time()

        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls if now - call_time < 60]

        # If we're at the limit, wait based on per-minute budget
        if self.calls_per_minute and len(self.calls) >= self.calls_per_minute:
            oldest_call = min(self.calls)
            wait_time = 60 - (now - oldest_call)
            if wait_time > 0:
                time.sleep(wait_time)
            now = time.time()

        # Record this call
        self.calls.append(now)


class HTTPClient:
    """Unified HTTP client for all providers with automatic features."""

    _tls_warning_suppressed = False

    def __init__(
        self,
        provider_name: str,
        config: Optional[Dict[str, Any]] = None,
        logger=None,
        *,
        timeout: float = 15.0,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        rate_limit_per_minute: int = 60,
        verifycert: bool = True,
        rate_limit_delay: Optional[float] = None,
    ):
        self.provider_name = provider_name

        # Normalize config into attribute-accessible object
        if config is None:
            config = {}
        if isinstance(config, dict):
            base = {
                "timeout": timeout,
                "max_retries": max_retries,
                "backoff_factor": backoff_factor,
                "rate_limit_per_minute": rate_limit_per_minute,
                "verifycert": verifycert,
            }
            # Support alternative rate limiting parameter (delay in seconds between calls)
            if rate_limit_delay is not None and rate_limit_delay > 0:
                try:
                    base["rate_limit_per_minute"] = max(1, int(60 / rate_limit_delay))
                except Exception:
                    pass
            # user-supplied dict overrides keyword defaults
            base.update(config)
            self.config = ConfigDict(base)
        else:
            # Assume it already provides attributes used below
            self.config = config
            # Fill in any missing attributes with keyword defaults
            if not hasattr(self.config, "timeout"):
                self.config.timeout = timeout
            if not hasattr(self.config, "max_retries"):
                self.config.max_retries = max_retries
            if not hasattr(self.config, "rate_limit_per_minute"):
                self.config.rate_limit_per_minute = rate_limit_per_minute
            if not hasattr(self.config, "verifycert"):
                self.config.verifycert = verifycert
            if not hasattr(self.config, "backoff_factor"):
                self.config.backoff_factor = backoff_factor

        self.logger = logger

        # Set up rate limiting
        self.rate_limiter = RateLimiter(
            self.config.rate_limit_per_minute,
            delay_seconds=rate_limit_delay,
        )

        # Set up session with retry strategy
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=self.config.backoff_factor,
            respect_retry_after_header=True,
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # If SSL verification is explicitly disabled on this config,
        # suppress noisy InsecureRequestWarning globally (once per process)
        if (
            getattr(self.config, "verifycert", True) is False
            and not HTTPClient._tls_warning_suppressed
        ):
            try:
                import warnings

                from urllib3.exceptions import InsecureRequestWarning

                warnings.simplefilter("once", InsecureRequestWarning)
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                HTTPClient._tls_warning_suppressed = True
            except Exception:
                pass

        # Set default headers
        self.session.headers.update(
            {
                "User-Agent": f"url-checker-tools/1.0 ({provider_name} provider)",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], float]:
        """Make GET request with automatic features."""
        return self._make_request("GET", url, headers=headers, params=params)

    def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], float]:
        """Make POST request with automatic features."""
        return self._make_request(
            "POST", url, headers=headers, data=data, json=json_data
        )

    def put(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], float]:
        """Make PUT request with automatic features."""
        return self._make_request(
            "PUT", url, headers=headers, data=data, json=json_data
        )

    def _make_request(
        self, method: str, url: str, **kwargs
    ) -> Tuple[Dict[str, Any], float]:
        """Make HTTP request with all automatic features."""
        # Security validation
        self._validate_url_security(url)

        # Rate limiting
        self.rate_limiter.wait_if_needed()

        # Log request
        start_time = time.time()
        self._log_request(method, url, kwargs)

        try:
            # Make the request
            # Add SSL verification setting for MISP and other providers that need it
            request_kwargs = kwargs.copy()
            if hasattr(self.config, "verifycert"):
                request_kwargs["verify"] = self.config.verifycert

            # Try using requests directly for patched functions in tests
            request_func = requests.request
            if method.upper() == "GET" and hasattr(requests, "get"):
                request_func = requests.get
            elif method.upper() == "POST" and hasattr(requests, "post"):
                request_func = requests.post
            elif method.upper() == "PUT" and hasattr(requests, "put"):
                request_func = requests.put

            last_exc: Optional[Exception] = None
            for attempt in range(int(getattr(self.config, "max_retries", 0)) + 1):
                try:
                    response = request_func(
                        url, timeout=self.config.timeout, **request_kwargs
                    )
                    break
                except requests.RequestException as rexc:
                    last_exc = rexc
                    # On final attempt, re-raise
                    if attempt >= int(getattr(self.config, "max_retries", 0)):
                        raise
                    # Backoff before retry
                    time.sleep(float(getattr(self.config, "backoff_factor", 1.0)))
            else:
                # Should not reach here; if so, raise last exception
                if last_exc:
                    raise last_exc

            execution_time = time.time() - start_time

            # Handle response
            # If using high-level requests methods, they might not auto-raise; ensure status check
            if hasattr(response, "raise_for_status"):
                response.raise_for_status()

            # Try to parse JSON
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                response_data = {
                    "raw_text": response.text,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                }

            # Log successful response
            self._log_response(url, response_data, execution_time)

            return response_data, execution_time

        except requests.RequestException as e:
            execution_time = time.time() - start_time
            error_msg = f"{method} request to {url} failed: {str(e)}"

            # Log error
            self._log_error(url, error_msg, execution_time)

            # Raise domain-specific error for tests expecting exceptions
            from .exceptions import APIRequestError

            raise APIRequestError(error_msg)

    def _validate_url_security(self, url: str) -> None:
        """Validate URL for security concerns."""
        parsed = urlparse(url)

        # Must be HTTPS for external APIs (except localhost)
        if parsed.scheme != "https" and parsed.hostname not in [
            "localhost",
            "127.0.0.1",
        ]:
            if self.config.verbose:
                print(
                    f"[WARNING] {self.provider_name}: Using HTTP instead of HTTPS for {url}"
                )

        # Block private IP ranges and localhost for external requests
        if parsed.hostname:
            hostname = parsed.hostname.lower()
            if hostname in ["localhost", "127.0.0.1"] and "localhost" not in url:
                raise ValueError(f"Security: Blocking localhost request: {url}")

            # Block common private IP patterns
            private_patterns = ["192.168.", "10.", "172.16.", "172.17.", "172.18."]
            if any(hostname.startswith(pattern) for pattern in private_patterns):
                raise ValueError(f"Security: Blocking private IP request: {url}")

    def _log_request(self, method: str, url: str, kwargs: Dict[str, Any]) -> None:
        """Log outgoing request."""
        if not self.logger:
            return

        # Sanitize sensitive data
        safe_kwargs = kwargs.copy()
        if "headers" in safe_kwargs and safe_kwargs["headers"]:
            safe_headers = {}
            for key, value in safe_kwargs["headers"].items():
                if (
                    "key" in key.lower()
                    or "token" in key.lower()
                    or "auth" in key.lower()
                ):
                    safe_headers[key] = "[REDACTED]"
                else:
                    safe_headers[key] = value
            safe_kwargs["headers"] = safe_headers

        self.logger.log_request(
            target=url,
            provider=self.provider_name,
            request_data={"method": method, "url": url, "kwargs": safe_kwargs},
        )

    def _log_response(
        self, url: str, response_data: Dict[str, Any], execution_time: float
    ) -> None:
        """Log successful response."""
        if not self.logger:
            return

        self.logger.log_result(
            target=url,
            provider=self.provider_name,
            result_data={
                "success": True,
                "execution_time": execution_time,
                "response_size": len(str(response_data)),
                "has_data": bool(response_data),
            },
        )

    def _log_error(self, url: str, error_msg: str, execution_time: float) -> None:
        """Log request error."""
        if not self.logger:
            return

        # Skip logging expected 404s during URLScan result polling
        if self.provider_name == "urlscan" and "404" in error_msg and "/result/" in url:
            return

        self.logger.log_error(
            target=url,
            provider=self.provider_name,
            error=error_msg,
            context={"execution_time": execution_time},
        )

    def close(self) -> None:
        """Close the HTTP session."""
        if self.session:
            self.session.close()
