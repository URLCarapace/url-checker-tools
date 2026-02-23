"""
URLChecker - Clean threat intelligence tool with modern architecture.

A streamlined tool for checking URLs and domains against multiple
threat intelligence sources with distributed Celery workflows.
"""

# Import core components of new architecture
from urlchecker.core.results import ProviderResult, ThreatLevel, WorkflowResult
from urlchecker.output.formatters import get_formatter
from urlchecker.workflows.orchestrator import WorkflowOrchestrator

__version__ = "0.1.0"
__author__ = "URLChecker Team"

__all__ = [
    "ProviderResult",
    "WorkflowResult",
    "ThreatLevel",
    "WorkflowOrchestrator",
    "get_formatter",
]
