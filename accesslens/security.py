"""Security and SSRF protection module for AccessLens AI.

Enforces strict URL scheme validation, hostname resolution checks, private/loopback
IP blocking, and redirect destination re-verification.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class SecurityError(Exception):
    """Raised when a URL violates safety or SSRF restrictions."""


class URLValidator:
    """Validates URLs to protect against SSRF, arbitrary schemes, and private IP access."""

    ALLOWED_SCHEMES = frozenset({"http", "https"})

    # Known cloud metadata and carrier-grade NAT networks
    CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")
    CLOUD_METADATA_IP = ipaddress.ip_address("169.254.169.254")

    @classmethod
    def is_private_or_restricted(cls, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if an IP address belongs to loopback, private, link-local, or reserved spaces."""
        if ip.is_loopback:
            return True
        if ip.is_private:
            return True
        if ip.is_link_local:
            return True
        if ip.is_multicast:
            return True
        if ip.is_reserved:
            return True
        if ip.is_unspecified:
            return True
        if ip == cls.CLOUD_METADATA_IP:
            return True
        if isinstance(ip, ipaddress.IPv4Address) and ip in cls.CARRIER_GRADE_NAT:
            return True
        return False

    @classmethod
    def resolve_and_verify_host(cls, hostname: str, allow_local: bool = False) -> list[str]:
        """Resolve hostname to IPs and verify none reside in forbidden network spaces."""
        clean_host = hostname.strip().strip("[]").lower()

        # Check for obvious local/internal names
        if not allow_local:
            if clean_host in {"localhost", "0.0.0.0", "127.0.0.1", "::1"}:
                raise SecurityError(
                    f"Blocked access to local host '{clean_host}'. Local/private scanning is prohibited by default."
                )
            if clean_host.endswith((".localhost", ".local", ".internal", ".lan")):
                raise SecurityError(
                    f"Blocked access to internal domain '{clean_host}'. Internal domain scanning is prohibited."
                )

        # Check if hostname is already an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            if not allow_local and cls.is_private_or_restricted(ip_obj):
                raise SecurityError(
                    f"Blocked direct IP '{clean_host}': address belongs to private/restricted IP range."
                )
            return [str(ip_obj)]
        except ValueError:
            pass  # It is a domain name, proceed to DNS resolution

        # Resolve DNS addresses
        resolved_ips: list[str] = []
        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                resolved_ips.append(ip_str)
        except socket.gaierror as exc:
            raise SecurityError(f"DNS resolution failed for host '{clean_host}': {exc}") from exc

        if not resolved_ips:
            raise SecurityError(f"Host '{clean_host}' did not resolve to any IP addresses.")

        if not allow_local:
            for ip_str in resolved_ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if cls.is_private_or_restricted(ip_obj):
                        raise SecurityError(
                            f"Host '{clean_host}' resolved to restricted address {ip_str} (SSRF protection)."
                        )
                except ValueError as exc:
                    raise SecurityError(f"Invalid resolved IP '{ip_str}': {exc}") from exc

        return resolved_ips

    @classmethod
    def validate_url(cls, url: str, allow_local: bool = False) -> str:
        """Validate that a URL has an allowed scheme and does not target restricted network destinations."""
        if not url or not isinstance(url, str):
            raise SecurityError("URL must be a non-empty string.")

        url_stripped = url.strip()
        parsed = urlsplit(url_stripped)

        # 1. Scheme check
        scheme = parsed.scheme.lower()
        if not scheme:
            raise SecurityError("Missing URL scheme. URL must begin with http:// or https://")
        if scheme not in cls.ALLOWED_SCHEMES:
            raise SecurityError(
                f"Disallowed URL scheme '{scheme}'. Only http and https schemes are permitted."
            )

        # 2. Host check
        hostname = parsed.hostname
        if not hostname:
            raise SecurityError(f"URL '{url_stripped}' is missing a valid hostname.")

        # 3. Port check
        if parsed.port is not None:
            if parsed.port < 1 or parsed.port > 65535:
                raise SecurityError(f"Invalid port number {parsed.port}.")

        # 4. Resolve host and check SSRF
        cls.resolve_and_verify_host(hostname, allow_local=allow_local)

        return url_stripped

    @classmethod
    def validate_redirect(cls, target_url: str, allow_local: bool = False) -> str:
        """Re-verify redirect destination URL against security policies."""
        try:
            return cls.validate_url(target_url, allow_local=allow_local)
        except SecurityError as err:
            raise SecurityError(f"Redirect destination rejected: {err}") from err
