#!/usr/bin/env python3
"""Clean formatter system using inheritance."""

import json
from abc import ABC, abstractmethod

from url_checker_tools.core.results import ProviderResult, ThreatLevel, WorkflowResult


class BaseFormatter(ABC):
    """Base formatter class that all output formatters inherit from."""

    @abstractmethod
    def format_provider_result(self, result: ProviderResult) -> str:
        """Format a single provider result."""
        pass

    @abstractmethod
    def format_workflow_result(self, result: WorkflowResult) -> str:
        """Format a complete workflow result."""
        pass


class TerminalFormatter(BaseFormatter):
    """Human-readable terminal output formatter."""

    def format_provider_result(self, result: ProviderResult) -> str:
        """Format provider result for terminal display."""
        status_icon = self._get_status_icon(result.threat_level)

        output = f"{status_icon} {result.provider.upper()}: "

        if result.is_error:
            output += f"ERROR - {result.error_message}"
        elif result.is_threat:
            output += f"{result.threat_level.value.upper()} (confidence: {result.confidence:.1%})"
        else:
            output += f"SAFE (confidence: {result.confidence:.1%})"

        if result.execution_time:
            output += f" [{result.execution_time:.2f}s]"

        return output

    def format_workflow_result(self, result: WorkflowResult) -> str:
        """Format workflow result for terminal display."""
        lines = []

        # Header
        lines.append("=" * 60)
        lines.append(f"URL SCAN RESULTS: {result.target}")
        lines.append(f"Workflow ID: {result.workflow_id}")
        lines.append("=" * 60)

        # Individual results
        for provider_result in result.results:
            lines.append(self.format_provider_result(provider_result))

        # Summary
        lines.append("-" * 60)
        lines.append(f"FINAL ASSESSMENT: {result.final_assessment.value.upper()}")
        lines.append(f"RECOMMENDATION: {result.recommendation.value.upper()}")
        lines.append(f"CONFIDENCE: {result.confidence_score:.1%}")
        lines.append(
            f"PROVIDERS: {result.provider_count} | ERRORS: {result.error_count}"
        )

        if result.total_execution_time:
            lines.append(f"TOTAL TIME: {result.total_execution_time:.2f}s")

        lines.append("=" * 60)

        return "\n".join(lines)

    def _get_status_icon(self, threat_level: ThreatLevel) -> str:
        """Get icon for threat level."""
        icons = {
            ThreatLevel.SAFE: "✓",
            ThreatLevel.SUSPICIOUS: "⚠",
            ThreatLevel.MALICIOUS: "⚠",
            ThreatLevel.CRITICAL: "⚠",
            ThreatLevel.UNKNOWN: "?",
            ThreatLevel.ERROR: "x",
        }
        return icons.get(threat_level, "?")


class JSONFormatter(BaseFormatter):
    """JSON output formatter for machine-readable results."""

    def format_provider_result(self, result: ProviderResult) -> str:
        """Format provider result as JSON."""
        return json.dumps(
            {
                "provider": result.provider,
                "target": result.target,
                "is_threat": result.is_threat,
                "threat_level": result.threat_level.value,
                "confidence": result.confidence,
                "execution_time": result.execution_time,
                "error_message": result.error_message,
                "timestamp": result.timestamp.isoformat(),
                "details": result.details,
            },
            indent=2,
        )

    def format_workflow_result(self, result: WorkflowResult) -> str:
        """Format workflow result as JSON."""
        return json.dumps(result.to_dict(), indent=2)


class CompactFormatter(BaseFormatter):
    """Compact one-line formatter for logging."""

    def format_provider_result(self, result: ProviderResult) -> str:
        """Format provider result in compact format."""
        status = "ERROR" if result.is_error else result.threat_level.value.upper()
        return (
            f"[{result.provider}] {result.target} -> {status} ({result.confidence:.1%})"
        )

    def format_workflow_result(self, result: WorkflowResult) -> str:
        """Format workflow result in compact format."""
        return (
            f"[WORKFLOW] {result.workflow_id[:8]} | {result.target} -> "
            f"{result.final_assessment.value.upper()} | "
            f"{result.recommendation.value} | "
            f"{result.provider_count} providers | "
            f"{result.confidence_score:.1%} confidence"
        )


class SynthesisFormatter(BaseFormatter):
    """Synthesis formatter for automated threat assessment."""

    def format_provider_result(self, result: ProviderResult) -> str:
        """Format single provider result for synthesis (not typically used)."""
        return json.dumps(
            {
                "provider": result.provider,
                "threat_detected": result.is_threat,
                "threat_level": result.threat_level.value,
                "confidence": result.confidence,
            },
            indent=2,
        )

    def format_workflow_result(self, result: WorkflowResult) -> str:
        """Format workflow result as synthesis."""
        return json.dumps(result.to_dict(), indent=2)


def get_formatter(format_type: str = "human") -> BaseFormatter:
    """Get formatter instance by type."""
    formatters = {
        "human": TerminalFormatter,  # Human-readable output
        "json": JSONFormatter,
        "compact": CompactFormatter,
        "synthesis": SynthesisFormatter,
    }

    formatter_class = formatters.get(format_type.lower())
    if not formatter_class:
        raise ValueError(f"Unknown formatter type: {format_type}")

    return formatter_class()
