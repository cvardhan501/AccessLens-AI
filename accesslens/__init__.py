"""AccessLens AI — Automated Web Accessibility Scanning Engine.

Built with Playwright and axe-core for deterministic, verifiable accessibility scanning,
paired with Strands Decider 2B action classification and Amazon Bedrock explanations.
"""

from .config import Settings, load_config
from .decider import (
    AccessibilityDecider,
    DeciderAuthError,
    DeciderError,
    DeciderQuotaError,
    DeciderRateLimitError,
    DeciderUnavailableError,
    DeciderValidationError,
    DecisionResult,
)
from .bedrock import (
    AccessibilityExplanation,
    BedrockAuthError,
    BedrockError,
    BedrockExplainer,
    BedrockUnavailableError,
)
from .models import ElementNode, ScanReport, ScanSummary, Violation
from .scanner import AccessibilityScanner, ScanError, SecurityError
from .security import URLValidator

__version__ = "0.2.0"
__all__ = [
    "AccessibilityScanner",
    "ScanReport",
    "Violation",
    "ElementNode",
    "ScanSummary",
    "ScanError",
    "SecurityError",
    "URLValidator",
    "Settings",
    "load_config",
    "AccessibilityDecider",
    "DecisionResult",
    "DeciderError",
    "DeciderAuthError",
    "DeciderQuotaError",
    "DeciderRateLimitError",
    "DeciderUnavailableError",
    "DeciderValidationError",
    "BedrockExplainer",
    "AccessibilityExplanation",
    "BedrockError",
    "BedrockAuthError",
    "BedrockUnavailableError",
]
