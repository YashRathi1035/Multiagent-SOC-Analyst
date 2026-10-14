"""Unit tests for LLM interface, Mock fallback, and Report Generation."""

from agents.llm_client import MockLLMClient, OllamaLLMClient
from data.test_cases.scenarios import (
    SYNTHETIC_BRUTE_FORCE_LOG,
    SYNTHETIC_PROMPT_INJECTION_LOG,
)
from detection.rules import DetectionEngine
from ingestion.parsers import parse_openssh_log
from ingestion.normalize import normalize_events
from models.schemas import InvestigationReport
from reports.generator import (
    InvestigationGenerator,
    export_report_to_json,
    export_report_to_markdown,
)


def test_mock_llm_client_structured():
    client = MockLLMClient()
    available, msg = client.is_available()
    assert available is True

    prompt = "INVESTIGATE CASE-1234 ALT-ABCD with EVT-0001-TEST from 192.168.1.100"
    report = client.generate_structured(prompt, InvestigationReport)

    assert isinstance(report, InvestigationReport)
    assert report.case_id == "CASE-1234"
    assert report.alert_id == "ALT-ABCD"
    assert report.confidence_score > 0.0
    assert len(report.observed_facts) > 0
    assert len(report.recommended_actions) > 0


def test_ollama_client_check():
    client = OllamaLLMClient()
    available, msg = client.is_available()
    # Should return a boolean and a descriptive string without unhandled exceptions
    assert isinstance(available, bool)
    assert isinstance(msg, str)


from rag.embeddings import EmbeddingManager
from rag.retrieve import RAGRetriever
from agents.threat_intel_agent import ThreatIntelAgent
from tools.reputation import ThreatIntelService


def test_investigation_generator_with_mock():
    records, _ = parse_openssh_log(SYNTHETIC_BRUTE_FORCE_LOG, year=2026)
    events, _ = normalize_events(records)
    engine = DetectionEngine()
    alerts = engine.run_all_rules(events)
    assert len(alerts) > 0

    mock_client = MockLLMClient()
    mock_retriever = RAGRetriever(embedding_manager=EmbeddingManager(force_mock=True))
    mock_ti = ThreatIntelAgent(service=ThreatIntelService(force_mock=True))
    generator = InvestigationGenerator(
        llm_client=mock_client,
        retriever=mock_retriever,
        threat_intel_agent=mock_ti,
    )
    report = generator.investigate_alert(alerts[0], events, case_id="CASE-TEST-001")

    assert report.case_id == "CASE-TEST-001"
    assert report.alert_id == alerts[0].alert_id
    assert len(report.triggering_events) > 0

    # Test markdown and JSON exports
    md = export_report_to_markdown(report)
    assert "# Security Incident Investigation Report" in md
    assert "CASE-TEST-001" in md
    assert "External Threat Intelligence" in md

    js = export_report_to_json(report)
    assert '"case_id": "CASE-TEST-001"' in js


def test_prompt_injection_safety():
    # Verify that malicious prompt injection logs do not break parsing or report generation
    records, _ = parse_openssh_log(SYNTHETIC_PROMPT_INJECTION_LOG, year=2026)
    events, _ = normalize_events(records)
    engine = DetectionEngine(brute_force_threshold=4)
    alerts = engine.run_all_rules(events)

    mock_retriever = RAGRetriever(embedding_manager=EmbeddingManager(force_mock=True))
    mock_ti = ThreatIntelAgent(service=ThreatIntelService(force_mock=True))
    generator = InvestigationGenerator(
        llm_client=MockLLMClient(),
        retriever=mock_retriever,
        threat_intel_agent=mock_ti,
    )
    if alerts:
        report = generator.investigate_alert(alerts[0], events)
        assert isinstance(report, InvestigationReport)
        # Verify markdown export doesn't fail
        md = export_report_to_markdown(report)
        assert len(md) > 100
