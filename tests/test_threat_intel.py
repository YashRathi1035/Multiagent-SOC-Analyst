"""Unit and integration tests for Threat Intelligence enrichment and Agent 3."""

import pytest
from agents.threat_intel_agent import ThreatIntelAgent
from models.schemas import ThreatIntelResult
from tools.reputation import (
    AbuseIPDBProvider,
    MockThreatIntelProvider,
    ThreatIntelService,
    VirusTotalProvider,
    extract_indicators_from_text,
    is_private_ip,
)


def test_indicator_extraction():
    sample_text = (
        "Adversary from 187.141.143.180 attacked internal host 10.0.0.5 communicating with "
        "evil-c2.malicious-domain.com and dropped payload with hash "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    extracted = extract_indicators_from_text(sample_text)

    assert "187.141.143.180" in extracted["ipv4"]
    assert "10.0.0.5" in extracted["ipv4"]
    assert "evil-c2.malicious-domain.com" in extracted["domains"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in extracted["sha256"]


def test_private_ip_detection():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("172.16.5.20") is True
    assert is_private_ip("127.0.0.1") is True

    # Public routable IPs
    assert is_private_ip("187.141.143.180") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("203.0.113.88") is False

    # Invalid strings
    assert is_private_ip("not-an-ip") is False


def test_mock_threat_intel_lookup():
    provider = MockThreatIntelProvider()

    # Test known malicious brute-forcer
    res_malicious = provider.lookup_ip("187.141.143.180")
    assert isinstance(res_malicious, ThreatIntelResult)
    assert res_malicious.is_malicious is True
    assert res_malicious.reputation_score >= 90.0
    assert "Brute-Force" in (res_malicious.threat_category or "")
    assert res_malicious.total_reports > 100
    assert res_malicious.country_code == "MX"

    # Test internal private IP (must never be treated as malicious)
    res_private = provider.lookup_ip("10.0.0.15")
    assert res_private.is_malicious is False
    assert res_private.reputation_score == 0.0
    assert "Private" in (res_private.threat_category or "")

    # Test clean external host
    res_clean = provider.lookup_ip("116.231.72.68")
    assert res_clean.is_malicious is False
    assert res_clean.reputation_score == 0.0


def test_threat_intel_service_caching():
    service = ThreatIntelService(force_mock=True)

    # First lookup
    res1 = service.enrich_ip("187.141.143.180")
    assert "187.141.143.180" in service._cache

    # Second lookup should return cached object
    res2 = service.enrich_ip("187.141.143.180")
    assert res1 is res2


def test_threat_intel_agent_analysis():
    agent = ThreatIntelAgent(service=ThreatIntelService(force_mock=True))
    ips = ["187.141.143.180", "10.0.0.15", "116.231.72.68"]

    analysis = agent.analyze_indicators(ips)

    assert analysis["total_indicators_queried"] == 3
    assert analysis["malicious_count"] == 1
    assert analysis["internal_count"] == 1
    assert analysis["clean_count"] == 1
    assert analysis["threat_severity"] == "HIGH"
    assert "187.141.143.180" in analysis["malicious_ips"]
    assert "CRITICAL REPUTATION" in analysis["summary"]

    formatted_prompt = agent.format_threat_intel_for_prompt(analysis)
    assert "Overall Threat Reputation: HIGH" in formatted_prompt
    assert "187.141.143.180" in formatted_prompt


def test_external_providers_missing_key_graceful():
    # AbuseIPDB with empty key
    abuse_provider = AbuseIPDBProvider(api_key="")
    res_abuse = abuse_provider.lookup_ip("8.8.8.8")
    assert res_abuse.error_message is not None
    assert "API key not configured" in res_abuse.error_message

    # VirusTotal with empty key
    vt_provider = VirusTotalProvider(api_key="")
    res_vt = vt_provider.lookup_ip("8.8.8.8")
    assert res_vt.error_message is not None
    assert "API key not configured" in res_vt.error_message

    # Private IP check on external providers should never make HTTP calls
    res_abuse_priv = abuse_provider.lookup_ip("192.168.1.1")
    assert "Private" in (res_abuse_priv.threat_category or "")
    assert res_abuse_priv.error_message is None
