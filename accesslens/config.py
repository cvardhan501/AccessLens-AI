"""Safe configuration manager for AccessLens AI.

Reads settings from local `.env` and environment variables. Never overrides
explicitly set process environment variables. Redacts sensitive credentials
from all string representations, representations, and log outputs.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent

# Default endpoints and models
DEFAULT_UGMDU_DECIDER_URL = "https://da25tnxy06gjk.cloudfront.net"
DEFAULT_LOCAL_DECIDER_URL = "http://127.0.0.1:8099"
DEFAULT_BEDROCK_MODEL = "us.amazon.nova-pro-v1:0"
DEFAULT_SMALL_MODEL = "us.amazon.nova-micro-v1:0"
DEFAULT_MEDIUM_MODEL = "us.amazon.nova-lite-v1:0"
DEFAULT_CONFIDENCE_THRESHOLD = 0.70


_DEFAULT_DOTENV_LOADED = False


def load_dotenv(env_path: Path | None = None) -> None:
    """Read a .env file and setdefault into os.environ without overriding existing vars."""
    global _DEFAULT_DOTENV_LOADED
    if env_path is None and _DEFAULT_DOTENV_LOADED:
        return

    search_paths = []
    if env_path:
        search_paths.append(Path(env_path))
    else:
        # Check AccessLens-AI root first, then workspace root
        search_paths.append(PROJECT_ROOT / ".env")
        search_paths.append(WORKSPACE_ROOT / ".env")

    for path in search_paths:
        if path.exists() and path.is_file():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    k = key.strip()
                    val = val.strip()
                    # Strip unquoted inline comments
                    if not (val.startswith('"') and val.endswith('"')) and not (val.startswith("'") and val.endswith("'")):
                        val = val.split("#", 1)[0]
                    v = val.strip().strip('"').strip("'")
                    # setdefault: never override variables already set in process environment
                    os.environ.setdefault(k, v)
                break  # Stop at first valid .env found
            except Exception:
                pass

    if env_path is None:
        _DEFAULT_DOTENV_LOADED = True


@dataclass(frozen=True)
class Settings:
    decider_mode: str
    decider_url: str
    decider_api_key: str
    llm_provider: str
    aws_region: str
    bedrock_model_id: str
    bedrock_small_model_id: str
    bedrock_medium_model_id: str
    bedrock_large_model_id: str
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD

    @property
    def has_decider_creds(self) -> bool:
        """Check if decider has required credentials for its mode."""
        if self.decider_mode == "local":
            return bool(self.decider_url)
        return bool(self.decider_api_key and self.decider_url)

    @property
    def has_bedrock_creds(self) -> bool:
        """Check if AWS credentials exist in environment or standard Boto3 credential chain."""
        has_direct = bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))
        has_profile = bool(os.environ.get("AWS_PROFILE"))
        has_bearer = bool(os.environ.get("AWS_BEARER_TOKEN_BEDROCK"))
        if has_direct or has_profile or has_bearer:
            return True
        try:
            import botocore.session
            session = botocore.session.get_session()
            return session.get_credentials() is not None
        except Exception:
            return False

    @property
    def masked_decider_api_key(self) -> str:
        """Return safe redacted representation of API key."""
        if not self.decider_api_key:
            return ""
        if len(self.decider_api_key) <= 8:
            return "***[REDACTED]***"
        return f"{self.decider_api_key[:4]}...{self.decider_api_key[-4:]}"

    def to_safe_dict(self) -> dict[str, Any]:
        """Return non-sensitive configuration dictionary."""
        is_bedrock = (self.llm_provider == "bedrock")
        bedrock_active = is_bedrock and self.has_bedrock_creds
        return {
            "mode": "decider-with-bedrock" if bedrock_active else "decider-only",
            "decider_mode": self.decider_mode,
            "decider_url": self.decider_url,
            "decider_configured": self.has_decider_creds,
            "decider_api_key": self.masked_decider_api_key,
            "llm_provider": self.llm_provider,
            "aws_region": self.aws_region,
            "bedrock_model_id": self.bedrock_model_id,
            "bedrock_configured": self.has_bedrock_creds,
            "bedrock_enabled": bedrock_active,
            "confidence_threshold": self.confidence_threshold,
        }

    def __repr__(self) -> str:
        return (
            f"Settings(decider_mode={self.decider_mode!r}, "
            f"decider_url={self.decider_url!r}, "
            f"decider_api_key={self.masked_decider_api_key!r}, "
            f"llm_provider={self.llm_provider!r}, "
            f"aws_region={self.aws_region!r}, "
            f"bedrock_model_id={self.bedrock_model_id!r}, "
            f"confidence_threshold={self.confidence_threshold})"
        )


def load_config(env_path: Path | None = None) -> Settings:
    """Load settings from environment after reading local .env file."""
    load_dotenv(env_path)

    mode = os.environ.get("DECIDER_MODE", "ugmdu").split("#")[0].strip().lower()
    default_url = DEFAULT_LOCAL_DECIDER_URL if mode == "local" else DEFAULT_UGMDU_DECIDER_URL
    url = os.environ.get("DECIDER_URL", default_url).split("#")[0].strip().rstrip("/")
    api_key = os.environ.get("DECIDER_API_KEY", "").split("#")[0].strip()

    provider = os.environ.get("LLM_PROVIDER", "disabled").split("#")[0].strip().lower()
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")).strip()
    main_model = os.environ.get("BEDROCK_MODEL_ID", DEFAULT_BEDROCK_MODEL).strip()
    small_model = os.environ.get("BEDROCK_SMALL_MODEL_ID", DEFAULT_SMALL_MODEL).strip()
    medium_model = os.environ.get("BEDROCK_MEDIUM_MODEL_ID", DEFAULT_MEDIUM_MODEL).strip()
    large_model = os.environ.get("BEDROCK_LARGE_MODEL_ID", main_model).strip()

    try:
        conf_thresh = float(os.environ.get("DECIDER_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD))
    except ValueError:
        conf_thresh = DEFAULT_CONFIDENCE_THRESHOLD

    return Settings(
        decider_mode=mode,
        decider_url=url,
        decider_api_key=api_key,
        llm_provider=provider,
        aws_region=region,
        bedrock_model_id=main_model,
        bedrock_small_model_id=small_model,
        bedrock_medium_model_id=medium_model,
        bedrock_large_model_id=large_model,
        confidence_threshold=conf_thresh,
    )
