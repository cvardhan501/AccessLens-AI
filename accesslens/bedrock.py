"""Amazon Bedrock accessibility explanation service powered by Strands Agents SDK.

Uses BedrockModel and structured output extraction to deliver grounded,
plain-language explanations, user impact insights, and concrete remediation
examples without claiming live verification or modifying target sites.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from pydantic import BaseModel, Field

from .config import Settings, load_config
from .decider import sanitize_html_evidence

logger = logging.getLogger("accesslens.bedrock")


class BedrockError(Exception):
    """Base error for Amazon Bedrock explanation service."""


class BedrockAuthError(BedrockError):
    """Raised when AWS credentials, SSO tokens, or session tokens are missing or expired."""


class BedrockAccessDeniedError(BedrockAuthError):
    """Raised when AWS IAM permissions are missing or account verification is pending."""


class BedrockInvalidModelError(BedrockError):
    """Raised when the specified model ID or inference profile is not found or unsupported in the region."""


class BedrockThrottlingError(BedrockError):
    """Raised when Bedrock API rate limit or quota is exceeded."""


class BedrockTimeoutError(BedrockError):
    """Raised when the connection or read timeout to Bedrock expires."""


class BedrockUnavailableError(BedrockError):
    """Raised when Bedrock endpoint or model is unreachable."""


class AccessibilityExplanation(BaseModel):
    """Structured explanation schema returned by Bedrock."""

    plain_language_explanation: str = Field(
        ...,
        description="Clear, accessible explanation of the specific violation.",
    )
    why_it_matters: str = Field(
        ...,
        description="How this barrier affects users navigating with assistive technologies or keyboard.",
    )
    proposed_remediation: str = Field(
        ...,
        description="Concrete, corrected HTML snippet strictly grounded in the provided element evidence.",
    )
    validation_steps: list[str] = Field(
        default_factory=list,
        description="Specific verification steps for developers and QA engineers to test the fix.",
    )
    limitations: str = Field(
        default="Advisory suggestion only. Code was not modified or verified on the live website.",
        description="Explicit limitation notice.",
    )
    confidence: str = Field(
        default="high",
        description="Certainty of the remediation recommendation (high, medium, low).",
    )


SYSTEM_PROMPT = """You are an expert digital accessibility engineer and WCAG auditor.
Your role is to explain automated axe-core accessibility findings and propose safe, minimal remediation code.
Strict Rules:
1. Ground your answer strictly in the provided HTML snippet and rule description.
2. Never invent unmentioned HTML elements, attributes, or site context.
3. If an image is purely decorative, explain alt="" or role="presentation". If it conveys content, explain descriptive alt text.
4. Always emphasize that code changes are advisory and have NOT been applied to the live website.
5. Provide concise, actionable validation steps (such as axe-core re-scan, screen reader announcement test, keyboard navigation test).
"""


class BedrockExplainer:
    """Invokes Amazon Bedrock models through the Strands Agents SDK."""

    def __init__(self, config: Settings | None = None):
        self.config = config or load_config()

    def explain_finding(
        self,
        rule_id: str,
        impact: str,
        description: str,
        target: list[str] | str,
        html: str,
        failure_summary: str,
        action_decision: str = "HUMAN_REVIEW",
    ) -> dict[str, Any]:
        """Generate structured explanation using Strands BedrockModel.
        
        Never called automatically at startup or during import.
        """
        if not self.config.has_bedrock_creds:
            raise BedrockAuthError(
                "AWS credentials not configured. Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or AWS_PROFILE "
                "in .env to enable Amazon Bedrock explanations."
            )

        clean_target = ", ".join(target) if isinstance(target, list) else str(target)
        clean_html = sanitize_html_evidence(html, max_chars=300)

        prompt = (
            f"Analyze this accessibility audit finding and provide remediation guidance:\n\n"
            f"Rule ID: {rule_id}\n"
            f"Severity Impact: {impact}\n"
            f"Rule Description: {description}\n"
            f"CSS Selector Target: {clean_target}\n"
            f"Failing Element HTML: {clean_html}\n"
            f"axe-core Failure Summary: {failure_summary}\n"
            f"Strands Decider Recommendation: {action_decision}\n\n"
            f"Provide a structured explanation, user impact assessment, corrected HTML example, "
            f"and validation steps."
        )

        t0 = time.perf_counter()
        try:
            import botocore.config
            from strands import Agent
            from strands.models import BedrockModel

            # Finite timeouts with zero retries prevent hanging threads
            boto_config = botocore.config.Config(
                connect_timeout=5,
                read_timeout=25,
                retries={"max_attempts": 0},
            )

            model = BedrockModel(
                model_id=self.config.bedrock_model_id,
                region_name=self.config.aws_region,
                boto_client_config=boto_config,
                max_tokens=600,
                temperature=0,
            )

            agent = Agent(
                model=model,
                system_prompt=SYSTEM_PROMPT,
                structured_output_model=AccessibilityExplanation,
                callback_handler=None,
            )

            result = agent(prompt, structured_output_model=AccessibilityExplanation)

        except Exception as exc:
            err_msg = str(exc)
            lower_msg = err_msg.lower()
            if any(term in lower_msg for term in ("accessdenied", "verification", "not authorized", "is not authorized")):
                logger.warning("Amazon Bedrock access denied or account verification pending: %s", err_msg)
                raise BedrockAccessDeniedError(
                    f"Bedrock access denied or account verification pending: {err_msg}"
                ) from exc
            if any(term in lower_msg for term in ("security token", "credentials", "unauthorized", "expired", "loginrefreshrequired", "reauthenticate", "nocredentialserror")):
                logger.warning("Amazon Bedrock authentication error (session expired or invalid credentials): %s", err_msg)
                raise BedrockAuthError(f"Bedrock authentication error: {err_msg}") from exc
            if any(term in lower_msg for term in ("resourcenotfound", "validationexception", "model not found", "unknown model", "inference profile", "unsupported model", "invalid model")):
                logger.warning("Amazon Bedrock model or region error: %s", err_msg)
                raise BedrockInvalidModelError(f"Bedrock model or region error: {err_msg}") from exc
            if any(term in lower_msg for term in ("throttling", "toomanyrequests", "rate limit", "limit exceeded", "requestlimitexceeded")):
                logger.warning("Amazon Bedrock rate limit exceeded: %s", err_msg)
                raise BedrockThrottlingError(f"Bedrock rate limit exceeded: {err_msg}") from exc
            if any(term in lower_msg for term in ("timeout", "timed out", "readtimeout", "connecttimeout")):
                logger.warning("Amazon Bedrock timeout error: %s", err_msg)
                raise BedrockTimeoutError(f"Bedrock request timed out: {err_msg}") from exc
            logger.warning("Amazon Bedrock service error: %s", err_msg)
            raise BedrockUnavailableError(f"Bedrock service error: {err_msg}") from exc

        elapsed_ms = (time.perf_counter() - t0) * 1000

        output = result.structured_output
        if isinstance(output, AccessibilityExplanation):
            data = output.model_dump()
        elif isinstance(output, dict):
            data = dict(output)
        elif hasattr(output, "__dict__"):
            data = dict(output.__dict__)
        else:
            # Fallback if text
            data = {
                "plain_language_explanation": str(result),
                "why_it_matters": "Impedes navigation for users with assistive technologies.",
                "proposed_remediation": clean_html,
                "validation_steps": ["Re-run axe-core audit to verify resolution."],
                "limitations": "Advisory suggestion only. Code was not modified on the live website.",
                "confidence": "medium",
            }

        data["model_id"] = self.config.bedrock_model_id
        data["latency_ms"] = round(elapsed_ms, 2)
        data["status"] = "success"
        return data
