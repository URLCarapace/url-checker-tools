#!/usr/bin/env python3
"""Shodan IP enrichment integration for threat intelligence."""

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import keyring
import requests

# TODO This module seems broken
from ..core.config import Config

logger = logging.getLogger(__name__)


class ShodanEnrichment:
    """Shodan API integration for IP address enrichment."""

    def __init__(self, rate_limit_delay: float = 1.0, cache_duration_hours: int = 24):
        """
        Initialize Shodan enrichment.

        Args:
            rate_limit_delay: Delay between API calls in seconds
            cache_duration_hours: How long to cache results
        """
        self.rate_limit_delay = rate_limit_delay
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self._api_key = None
        self._last_request_time = 0
        self._cache = {}  # Simple in-memory cache

    @property
    def api_key(self) -> Optional[str]:
        """Get Shodan API key from keyring."""
        if self._api_key is None:
            try:
                self._api_key = keyring.get_password(Config.SERVICE_NAME, "shodan")
                if self._api_key:
                    logger.debug("Shodan API key loaded from keyring")
                else:
                    logger.warning("No Shodan API key found in keyring")
            except Exception as e:
                logger.error(f"Failed to load Shodan API key from keyring: {e}")
        return self._api_key

    @property
    def is_available(self) -> bool:
        """Check if InternetDB integration is available (always True - no API key required)."""
        return True  # InternetDB doesn't require an API key

    def enrich_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich an IP address with InternetDB data (free Shodan service).

        Args:
            ip_address: IP address to enrich

        Returns:
            InternetDB enrichment data or None if failed
        """
        cached_result = self._get_cached_result(ip_address)
        if cached_result:
            logger.debug(f"Using cached InternetDB data for {ip_address}")
            return cached_result

        try:
            self._enforce_rate_limit()

            # Use InternetDB (free Shodan service) instead of paid API
            url = f"https://internetdb.shodan.io/{ip_address}"

            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                enrichment = self._process_internetdb_response(ip_address, data)
                self._cache_result(ip_address, enrichment)
                logger.info(f"Successfully enriched {ip_address} with InternetDB data")
                return enrichment

            elif response.status_code == 404:
                logger.debug(f"IP {ip_address} not found in InternetDB")
                empty_result = {
                    "ip": ip_address,
                    "found": False,
                    "reason": "not_in_internetdb",
                }
                self._cache_result(ip_address, empty_result)
                return empty_result

            else:
                logger.error(
                    f"InternetDB error for {ip_address}: {response.status_code} - {response.text}"
                )
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"InternetDB request failed for {ip_address}: {e}")
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error enriching {ip_address} with InternetDB: {e}"
            )
            return None

    def enrich_multiple_ips(
        self, ip_addresses: List[str]
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Enrich multiple IP addresses with Shodan data.

        Args:
            ip_addresses: List of IP addresses to enrich

        Returns:
            Dictionary mapping IP addresses to their enrichment data
        """
        results = {}

        for ip in ip_addresses:
            if ip:  # Skip empty/None IPs
                try:
                    results[ip] = self.enrich_ip(ip)
                except Exception as e:
                    logger.error(f"Failed to enrich IP {ip}: {e}")
                    results[ip] = None

        logger.info(
            f"Enriched {len([r for r in results.values() if r])} of {len(ip_addresses)} IPs with InternetDB data"
        )
        return results

    def _process_internetdb_response(
        self, ip: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process raw InternetDB API response into enrichment data."""
        enrichment = {
            "ip": ip,
            "found": True,
            "timestamp": datetime.now().isoformat(),
            "source": "internetdb",
        }

        # InternetDB provides: ip, ports, cpes, hostnames, tags, vulns
        enrichment["hostnames"] = data.get("hostnames", [])
        enrichment["open_ports"] = data.get("ports", [])
        enrichment["cpes"] = data.get("cpes", [])
        enrichment["tags"] = data.get("tags", [])

        # Process vulnerabilities
        vulns = data.get("vulns", [])
        if vulns:
            enrichment["vulnerabilities"] = {
                "total": len(vulns),
                "cves": vulns,
                "high_priority": [
                    cve
                    for cve in vulns
                    if any(severity in cve.lower() for severity in ["critical", "high"])
                ],
            }

        service_summary = {}
        for port in enrichment["open_ports"]:
            service_name = f"port-{port}"
            for cpe in enrichment["cpes"]:
                if str(port) in cpe:
                    parts = cpe.split(":")
                    if len(parts) > 3:
                        service_name = parts[3]
                    break

            if service_name not in service_summary:
                service_summary[service_name] = []
            service_summary[service_name].append(port)

        enrichment["service_summary"] = service_summary
        enrichment["total_services"] = len(service_summary)

        enrichment["risk_indicators"] = self._calculate_risk_indicators_internetdb(
            enrichment
        )

        return enrichment

    def _process_shodan_response(self, ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw Shodan API response into enrichment data."""
        enrichment = {
            "ip": ip,
            "found": True,
            "timestamp": datetime.now().isoformat(),
            "source": "shodan",
        }

        # Basic host info
        enrichment["hostnames"] = data.get("hostnames", [])
        enrichment["country_code"] = data.get("country_code")
        enrichment["country_name"] = data.get("country_name")
        enrichment["city"] = data.get("city")
        enrichment["region_code"] = data.get("region_code")
        enrichment["postal_code"] = data.get("postal_code")
        enrichment["latitude"] = data.get("latitude")
        enrichment["longitude"] = data.get("longitude")

        # ISP and organization info
        enrichment["isp"] = data.get("isp")
        enrichment["org"] = data.get("org")
        enrichment["asn"] = data.get("asn")

        # Process service data
        services = []
        ports = []
        service_summary = {}

        for service_data in data.get("data", []):
            port = service_data.get("port")
            if port:
                ports.append(port)

            service_info = {
                "port": port,
                "protocol": service_data.get("transport", "tcp"),
                "service": service_data.get("product"),
                "version": service_data.get("version"),
                "banner": (
                    service_data.get("banner", "")[:200]
                    if service_data.get("banner")
                    else None
                ),  # Truncate long banners
                "timestamp": service_data.get("timestamp"),
            }

            # Add SSL/TLS info if available
            if "ssl" in service_data:
                ssl_info = service_data["ssl"]
                service_info["ssl"] = {
                    "versions": ssl_info.get("versions", []),
                    "cipher": (
                        ssl_info.get("cipher", {}).get("name")
                        if ssl_info.get("cipher")
                        else None
                    ),
                    "cert_serial": (
                        ssl_info.get("cert", {}).get("serial")
                        if ssl_info.get("cert")
                        else None
                    ),
                }

            services.append(service_info)

            # Build service summary
            service_name = service_data.get("product") or f"port-{port}"
            if service_name not in service_summary:
                service_summary[service_name] = []
            service_summary[service_name].append(port)

        enrichment["services"] = services
        enrichment["open_ports"] = sorted(list(set(ports)))
        enrichment["service_summary"] = service_summary
        enrichment["total_services"] = len(services)

        # Add vulnerability info if present
        vulns = data.get("vulns", [])
        if vulns:
            enrichment["vulnerabilities"] = {
                "total": len(vulns),
                "cves": list(vulns),
                "high_priority": [
                    cve
                    for cve in vulns
                    if any(severity in cve.lower() for severity in ["critical", "high"])
                ],
            }

        # Add tags if present
        tags = data.get("tags", [])
        if tags:
            enrichment["tags"] = tags

        # Calculate risk indicators
        enrichment["risk_indicators"] = self._calculate_risk_indicators(enrichment)

        return enrichment

    def _calculate_risk_indicators(self, enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk indicators from Shodan data."""
        indicators = {
            "high_risk_ports": [],
            "suspicious_services": [],
            "vulnerability_count": 0,
            "risk_score": 0,
        }

        high_risk_ports = [
            21,
            22,
            23,
            135,
            139,
            445,
            1433,
            1521,
            3306,
            3389,
            5432,
            5900,
            6379,
        ]
        open_ports = enrichment.get("open_ports", [])

        for port in open_ports:
            if port in high_risk_ports:
                indicators["high_risk_ports"].append(port)

        services = enrichment.get("services", [])
        suspicious_keywords = ["backdoor", "trojan", "malware", "honeypot", "botnet"]

        for service in services:
            banner = service.get("banner", "").lower()
            service_name = service.get("service", "").lower()

            for keyword in suspicious_keywords:
                if keyword in banner or keyword in service_name:
                    indicators["suspicious_services"].append(
                        {
                            "port": service.get("port"),
                            "service": service.get("service"),
                            "reason": f"Contains '{keyword}'",
                        }
                    )

        vulns = enrichment.get("vulnerabilities", {})
        indicators["vulnerability_count"] = vulns.get("total", 0)

        risk_score = 0
        risk_score += (
            len(indicators["high_risk_ports"]) * 10
        )  # 10 points per high-risk port
        risk_score += (
            len(indicators["suspicious_services"]) * 20
        )  # 20 points per suspicious service
        risk_score += (
            indicators["vulnerability_count"] * 5
        )  # 5 points per vulnerability

        indicators["risk_score"] = min(risk_score, 100)  # Cap at 100

        return indicators

    def _calculate_risk_indicators_internetdb(
        self, enrichment: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate risk indicators from InternetDB data."""
        indicators = {
            "high_risk_ports": [],
            "suspicious_services": [],
            "vulnerability_count": 0,
            "risk_score": 0,
        }

        high_risk_ports = [
            21,
            22,
            23,
            135,
            139,
            445,
            1433,
            1521,
            3306,
            3389,
            5432,
            5900,
            6379,
        ]
        open_ports = enrichment.get("open_ports", [])

        for port in open_ports:
            if port in high_risk_ports:
                indicators["high_risk_ports"].append(port)

        tags = enrichment.get("tags", [])
        suspicious_tags = [
            "malware",
            "botnet",
            "honeypot",
            "compromised",
            "backdoor",
            "trojan",
        ]

        for tag in tags:
            tag_lower = tag.lower()
            for suspicious_keyword in suspicious_tags:
                if suspicious_keyword in tag_lower:
                    indicators["suspicious_services"].append(
                        {"tag": tag, "reason": f"Contains '{suspicious_keyword}'"}
                    )

        vulns = enrichment.get("vulnerabilities", {})
        indicators["vulnerability_count"] = vulns.get("total", 0)

        risk_score = 0
        risk_score += (
            len(indicators["high_risk_ports"]) * 10
        )  # 10 points per high-risk port
        risk_score += (
            len(indicators["suspicious_services"]) * 25
        )  # 25 points per suspicious service/tag
        risk_score += (
            indicators["vulnerability_count"] * 5
        )  # 5 points per vulnerability

        dangerous_tags = ["botnet", "malware", "compromised"]
        for tag in tags:
            if any(dangerous in tag.lower() for dangerous in dangerous_tags):
                risk_score += 30

        indicators["risk_score"] = min(risk_score, 100)  # Cap at 100

        return indicators

    def _enforce_rate_limit(self):
        """Enforce rate limiting between API calls."""
        current_time = time.time()
        time_since_last = current_time - self._last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            time.sleep(sleep_time)

        self._last_request_time = time.time()

    def _get_cached_result(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired."""
        if ip not in self._cache:
            return None

        cached_data, timestamp = self._cache[ip]

        if datetime.now() - timestamp < self.cache_duration:
            return cached_data
        else:
            del self._cache[ip]
            return None

    def _cache_result(self, ip: str, data: Dict[str, Any]):
        """Cache enrichment result."""
        self._cache[ip] = (data, datetime.now())

        if len(self._cache) > 1000:
            oldest_ip = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_ip]


def create_shodan_enrichment_summary(
    enrichment_results: Dict[str, Optional[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Create a summary of Shodan enrichment results for MISP integration."""
    summary = {
        "total_ips": len(enrichment_results),
        "enriched_ips": 0,
        "high_risk_ips": 0,
        "total_vulnerabilities": 0,
        "unique_services": set(),
        "countries": set(),
        "asns": set(),
        "risk_indicators": [],
    }

    for ip, data in enrichment_results.items():
        if data and data.get("found"):
            summary["enriched_ips"] += 1

            risk_indicators = data.get("risk_indicators", {})
            risk_score = risk_indicators.get("risk_score", 0)
            if risk_score > 50:  # Threshold for high risk
                summary["high_risk_ips"] += 1

            vulns = data.get("vulnerabilities", {})
            summary["total_vulnerabilities"] += vulns.get("total", 0)

            services = data.get("service_summary", {})
            summary["unique_services"].update(services.keys())

            if data.get("country_code"):
                summary["countries"].add(data["country_code"])
            if data.get("asn"):
                summary["asns"].add(data["asn"])

            if risk_indicators.get("high_risk_ports"):
                summary["risk_indicators"].append(
                    f"{ip}: High-risk ports {risk_indicators['high_risk_ports']}"
                )
            if risk_indicators.get("suspicious_services"):
                summary["risk_indicators"].append(f"{ip}: Suspicious services detected")
            if risk_indicators.get("vulnerability_count") > 0:
                summary["risk_indicators"].append(
                    f"{ip}: {risk_indicators['vulnerability_count']} vulnerabilities"
                )

    summary["unique_services"] = list(summary["unique_services"])
    summary["countries"] = list(summary["countries"])
    summary["asns"] = list(summary["asns"])

    return summary
