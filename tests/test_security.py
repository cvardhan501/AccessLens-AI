"""Unit tests for AccessLens AI security and SSRF protection."""

import pytest

from accesslens.security import SecurityError, URLValidator


def test_allowed_public_urls():
    """Valid public HTTP and HTTPS URLs pass validation."""
    valid_urls = [
        "https://example.com",
        "http://example.com/accessibility",
        "https://example.org:443/test?query=val",
    ]
    for url in valid_urls:
        validated = URLValidator.validate_url(url, allow_local=False)
        assert validated == url


def test_disallowed_schemes_rejected():
    """Unsafe schemes such as file://, javascript:, data:, and ftp:// are strictly blocked."""
    unsafe_urls = [
        "file:///C:/Windows/system32/drivers/etc/hosts",
        "file:///etc/passwd",
        "javascript:alert(document.cookie)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "ftp://ftp.example.com/secret",
        "gopher://gopher.example.com",
        "view-source:https://example.com",
        "about:blank",
    ]
    for url in unsafe_urls:
        with pytest.raises(SecurityError, match="Disallowed URL scheme|Missing URL scheme"):
            URLValidator.validate_url(url, allow_local=False)


def test_localhost_and_loopback_blocked_by_default():
    """Localhost and loopback IPs are blocked when allow_local is False."""
    local_urls = [
        "http://localhost",
        "http://localhost:8080/admin",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.2",
        "http://0.0.0.0",
        "http://[::1]",
    ]
    for url in local_urls:
        with pytest.raises(SecurityError, match="Blocked access to local host|Blocked direct IP"):
            URLValidator.validate_url(url, allow_local=False)


def test_private_rfc1918_ips_blocked():
    """Private RFC 1918 IPv4 ranges are blocked by default."""
    private_urls = [
        "http://10.0.0.1",
        "http://10.255.255.254:8080",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.1.1",
        "http://192.168.0.100:8443",
    ]
    for url in private_urls:
        with pytest.raises(SecurityError, match="Blocked direct IP.*address belongs to private/restricted IP range"):
            URLValidator.validate_url(url, allow_local=False)


def test_cloud_metadata_service_ip_blocked():
    """AWS and cloud provider metadata IP 169.254.169.254 is blocked."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(SecurityError, match="Blocked direct IP"):
        URLValidator.validate_url(metadata_url, allow_local=False)


def test_internal_domain_suffixes_blocked():
    """Internal domain names ending in .local, .internal, or .lan are blocked."""
    internal_urls = [
        "http://service.internal/api",
        "http://backend.local:9000",
        "http://database.lan",
    ]
    for url in internal_urls:
        with pytest.raises(SecurityError, match="Blocked access to internal domain"):
            URLValidator.validate_url(url, allow_local=False)


def test_allow_local_permits_testing_endpoints():
    """When allow_local=True, localhost endpoints for local testing are permitted."""
    allowed_local = [
        "http://localhost:8501",
        "http://127.0.0.1:8000/fixture",
    ]
    for url in allowed_local:
        res = URLValidator.validate_url(url, allow_local=True)
        assert res == url


def test_validate_redirect_blocks_unsafe_destinations():
    """Redirect validator prevents redirection into private or local endpoints."""
    # Safe redirect
    safe = URLValidator.validate_redirect("https://example.com/welcome", allow_local=False)
    assert safe == "https://example.com/welcome"

    # Unsafe redirect to loopback
    with pytest.raises(SecurityError, match="Redirect destination rejected"):
        URLValidator.validate_redirect("http://127.0.0.1:8080/internal-status", allow_local=False)

    # Unsafe redirect to cloud metadata
    with pytest.raises(SecurityError, match="Redirect destination rejected"):
        URLValidator.validate_redirect("http://169.254.169.254/credentials", allow_local=False)
