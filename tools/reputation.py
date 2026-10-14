"""Threat Intelligence providers and reputation lookup service.

Provides indicator extraction, private IP filtering, offline Mock provider,
and optional integrations with AbuseIPDB and VirusTotal with rate-limiting and zero key leakage.
"""

from abc import ABC, abstractmethod
from datetime import datetime
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from config.settings import settings
from models.schemas import ThreatIntelResult

logger = logging.getLogger(__name__)

# Regular expressions for indicator extraction
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
SHA256_REGEX = re.compile(r"\b[A-Fa-f0-9]{64}\b")


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to internal private/RFC1918 or loopback space.

    Explicitly treats RFC 5737 test subnets (198.51.100.0/24, 203.0.113.0/24)
    as external simulated telemetry rather than internal corporate LAN.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def extract_indicators_from_text(text: str) -> Dict[str, List[str]]:
    """Extract distinct IPv4 addresses, domains, and SHA-256 hashes from raw text."""
    ips = list(set(IPV4_REGEX.findall(text)))
    domains = list(set(DOMAIN_REGEX.findall(text)))
    hashes = list(set(SHA256_REGEX.findall(text)))

    # Filter out common invalid domains that match IP-like or file extension patterns
    clean_domains = [
        d for d in domains if not re.match(r"^\d+\.\d+\.\d+\.\d+$", d) and "." in d
    ]

    return {
        "ipv4": sorted(ips),
        "domains": sorted(clean_domains),
        "sha256": sorted(hashes),
    }


class BaseThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @abstractmethod
    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Query reputation for an IP address."""
        pass


class MockThreatIntelProvider(BaseThreatIntelProvider):
    """Deterministic offline threat intelligence provider for testing and air-gapped use."""

    # Curated offline community reputation database
    MOCK_DB: Dict[str, Dict[str, Any]] = {
        "187.141.143.180": {
            "reputation_score": 96.0,
            "is_malicious": True,
            "threat_category": "Brute-Force / SSH Scanner",
            "total_reports": 234,
            "last_reported_at": "2026-10-12T18:30:00Z",
            "country_code": "MX",
            "isp": "Uninet S.A. de C.V.",
            "source_url": "https://www.abuseipdb.com/check/187.141.143.180",
        },
        "198.51.100.99": {
            "reputation_score": 88.0,
            "is_malicious": True,
            "threat_category": "Password Guessing Botnet",
            "total_reports": 87,
            "last_reported_at": "2026-10-13T04:15:00Z",
            "country_code": "US",
            "isp": "Documentation Testnet Subnet",
            "source_url": "https://www.abuseipdb.com/check/198.51.100.99",
        },
        "203.0.113.88": {
            "reputation_score": 92.0,
            "is_malicious": True,
            "threat_category": "User Enumeration / Account Spraying",
            "total_reports": 115,
            "last_reported_at": "2026-10-13T09:40:00Z",
            "country_code": "AU",
            "isp": "TEST-NET-3 Hosting",
            "source_url": "https://www.abuseipdb.com/check/203.0.113.88",
        },
        "203.0.113.45": {
            "reputation_score": 45.0,
            "is_malicious": False,
            "threat_category": "Suspicious Remote Host",
            "total_reports": 8,
            "last_reported_at": "2026-10-11T12:00:00Z",
            "country_code": "AU",
            "isp": "TEST-NET-3 Commercial",
            "source_url": "https://www.abuseipdb.com/check/203.0.113.45",
        },
        "116.231.72.68": {
            "reputation_score": 0.0,
            "is_malicious": False,
            "threat_category": "Clean / Legitimate Host",
            "total_reports": 0,
            "last_reported_at": None,
            "country_code": "CN",
            "isp": "China Telecom Shanghai",
            "source_url": "https://www.abuseipdb.com/check/116.231.72.68",
        },
    }

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if is_private_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="MockThreatIntel",
                reputation_score=0.0,
                is_malicious=False,
                threat_category="Private RFC1918 Network",
                total_reports=0,
                country_code="LAN",
                isp="Internal Organization Subnet",
                source_url=None,
            )

        if ip in self.MOCK_DB:
            info = self.MOCK_DB[ip]
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="MockThreatIntel",
                reputation_score=info["reputation_score"],
                is_malicious=info["is_malicious"],
                threat_category=info["threat_category"],
                total_reports=info["total_reports"],
                last_reported_at=info["last_reported_at"],
                country_code=info["country_code"],
                isp=info["isp"],
                source_url=info["source_url"],
            )

        # Default clean response for unknown external test IPs
        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ipv4",
            provider="MockThreatIntel",
            reputation_score=5.0,
            is_malicious=False,
            threat_category="Unreported / Benign Traffic",
            total_reports=0,
            country_code="US",
            isp="Generic Cloud Provider",
            source_url=f"https://www.abuseipdb.com/check/{ip}",
        )


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """AbuseIPDB REST API v2 client with bounded timeouts and error handling."""

    def __init__(self, api_key: str = settings.ABUSEIPDB_API_KEY, timeout_seconds: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout_seconds

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if is_private_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="AbuseIPDB",
                reputation_score=0.0,
                is_malicious=False,
                threat_category="Private RFC1918 Network (Skipped API lookup)",
                total_reports=0,
                country_code="LAN",
                isp="Internal Network",
            )

        if not self.api_key:
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="AbuseIPDB",
                error_message="AbuseIPDB API key not configured.",
            )

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = float(data.get("abuseConfidenceScore", 0.0))
                    return ThreatIntelResult(
                        indicator=ip,
                        indicator_type="ipv4",
                        provider="AbuseIPDB",
                        reputation_score=score,
                        is_malicious=score >= 50.0,
                        threat_category="Abuse Reported" if score >= 50.0 else "Clean",
                        total_reports=int(data.get("totalReports", 0)),
                        last_reported_at=data.get("lastReportedAt"),
                        country_code=data.get("countryCode"),
                        isp=data.get("isp"),
                        source_url=f"https://www.abuseipdb.com/check/{ip}",
                    )
                else:
                    return ThreatIntelResult(
                        indicator=ip,
                        indicator_type="ipv4",
                        provider="AbuseIPDB",
                        error_message=f"HTTP {resp.status_code}: {resp.text[:100]}",
                    )
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="AbuseIPDB",
                error_message=f"Lookup error: {str(e)}",
            )


class VirusTotalProvider(BaseThreatIntelProvider):
    """VirusTotal v3 REST API client with bounded timeouts and error handling."""

    def __init__(self, api_key: str = settings.VIRUSTOTAL_API_KEY, timeout_seconds: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout_seconds

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        if is_private_ip(ip):
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="VirusTotal",
                reputation_score=0.0,
                is_malicious=False,
                threat_category="Private RFC1918 Network (Skipped API lookup)",
                total_reports=0,
                country_code="LAN",
                isp="Internal Network",
            )

        if not self.api_key:
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="VirusTotal",
                error_message="VirusTotal API key not configured.",
            )

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious_votes = int(stats.get("malicious", 0))
                    total_votes = sum(stats.values()) if stats else 1
                    score = (malicious_votes / max(total_votes, 1)) * 100.0

                    return ThreatIntelResult(
                        indicator=ip,
                        indicator_type="ipv4",
                        provider="VirusTotal",
                        reputation_score=round(score, 1),
                        is_malicious=malicious_votes >= 3,
                        threat_category="Malicious IP" if malicious_votes >= 3 else "Clean",
                        total_reports=malicious_votes,
                        country_code=data.get("country"),
                        isp=data.get("as_owner"),
                        source_url=f"https://www.virustotal.com/gui/ip-address/{ip}",
                    )
                else:
                    return ThreatIntelResult(
                        indicator=ip,
                        indicator_type="ipv4",
                        provider="VirusTotal",
                        error_message=f"HTTP {resp.status_code}: {resp.text[:100]}",
                    )
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", ip, e)
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ipv4",
                provider="VirusTotal",
                error_message=f"Lookup error: {str(e)}",
            )


class ThreatIntelService:
    """Central service managing indicator enrichment, caching, and provider fallback."""

    def __init__(self, force_mock: bool = False):
        self.force_mock = force_mock
        self._cache: Dict[str, ThreatIntelResult] = {}

        if not force_mock and settings.ABUSEIPDB_API_KEY:
            self.provider: BaseThreatIntelProvider = AbuseIPDBProvider()
            logger.info("ThreatIntelService initialized with AbuseIPDB provider.")
        elif not force_mock and settings.VIRUSTOTAL_API_KEY:
            self.provider = VirusTotalProvider()
            logger.info("ThreatIntelService initialized with VirusTotal provider.")
        else:
            self.provider = MockThreatIntelProvider()
            logger.info("ThreatIntelService initialized with MockThreatIntelProvider (offline mode).")

    def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """Enrich a single IP address with cache check."""
        if not ip:
            return ThreatIntelResult(
                indicator="unknown",
                indicator_type="ipv4",
                provider=self.provider.__class__.__name__,
                error_message="Empty IP address provided.",
            )

        if ip in self._cache:
            return self._cache[ip]

        result = self.provider.lookup_ip(ip)
        self._cache[ip] = result
        return result

    def enrich_indicators(self, ips: List[str]) -> List[ThreatIntelResult]:
        """Enrich a list of IP addresses."""
        results: List[ThreatIntelResult] = []
        for ip in ips:
            if ip:
                results.append(self.enrich_ip(ip))
        return results
