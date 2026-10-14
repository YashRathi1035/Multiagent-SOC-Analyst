"""AI-Powered Multi-Agent SOC Analyst - Streamlit Application.

Interactive Tier-3 Security Operations Center assistant for log ingestion,
deterministic rule detection, RAG-grounded AI investigation, and structured report generation.
"""

from datetime import datetime
import json
from pathlib import Path
import streamlit as st
import pandas as pd

from config.settings import settings
from models.schemas import EventOutcome, ReviewStatus, SeverityLevel
from ingestion.parsers import (
    IngestionError,
    parse_csv_log,
    parse_json_log,
    parse_openssh_log,
    validate_file_size,
)
from ingestion.normalize import normalize_events
from detection.rules import DetectionEngine
from agents.llm_client import MockLLMClient, OllamaLLMClient, get_llm_client
from rag.retrieve import RAGRetriever
from reports.generator import (
    InvestigationGenerator,
    export_report_to_json,
    export_report_to_markdown,
)

# Page configuration
st.set_page_config(
    page_title="AI Multi-Agent SOC Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber SOC Aesthetic CSS
st.markdown(
    """
<style>
    /* Global Background & Dark Theme Tweaks */
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* Header Container */
    .soc-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .soc-header h1 {
        margin: 0;
        font-size: 2.2rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: -0.5px;
    }
    .soc-header p {
        margin: 6px 0 0 0;
        color: #94a3b8;
        font-size: 1rem;
    }

    /* Metric Cards */
    .soc-metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .soc-metric-card:hover {
        transform: translateY(-2px);
        border-color: #38bdf8;
    }
    .metric-title {
        font-size: 0.82rem;
        text-transform: uppercase;
        color: #94a3b8;
        letter-spacing: 0.05em;
        font-weight: 600;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #f8fafc;
        margin-top: 4px;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-medium {
        background-color: #eab308;
        color: #0f172a;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-low {
        background-color: #3b82f6;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Report Card */
    .report-box {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-left: 4px solid #38bdf8;
        border-radius: 8px;
        padding: 20px;
        margin-top: 15px;
    }
</style>
""",
    unsafe_allow_html=True,
)

# Initialize Session State
if "events" not in st.session_state:
    st.session_state.events = []
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = None
if "report" not in st.session_state:
    st.session_state.report = None
if "warnings" not in st.session_state:
    st.session_state.warnings = []


# Check Ollama Status
def check_ollama_status():
    ollama = OllamaLLMClient()
    available, msg = ollama.is_available()
    return available, msg


ollama_online, ollama_msg = check_ollama_status()

# Top Navigation and Header
st.markdown(
    f"""
<div class="soc-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h1>🛡️ AI-Powered Multi-Agent SOC Analyst</h1>
            <p>Autonomous Tier-3 Security Operations Investigation & Evidence Correlation Platform</p>
        </div>
        <div style="text-align: right;">
            <span style="background: {'#15803d' if ollama_online else '#b45309'}; padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; color: white;">
                {'● Ollama Online (' + settings.OLLAMA_MODEL + ')' if ollama_online else '▲ Mock LLM Mode'}
            </span>
            <div style="font-size: 0.8rem; color: #38bdf8; margin-top: 5px; font-weight: 600;">
                Phase 2: RAG & MITRE ATT&CK Active (FAISS + all-MiniLM-L6-v2)
            </div>
        </div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# Sidebar Configuration
with st.sidebar:
    st.header("⚙️ Investigation Control")

    # Model Selection
    st.subheader("Model Runtime")
    model_mode = st.radio(
        "Inference Engine",
        ["Local Ollama (qwen3:4b)", "Deterministic Mock LLM (Fast/Offline)"],
        index=0 if ollama_online else 1,
        help="Select between live local Ollama Qwen3 model or fast deterministic mock model.",
    )
    use_mock = "Mock" in model_mode

    st.markdown("---")
    st.subheader("🎯 Detection Thresholds")
    brute_force_th = st.slider(
        "Brute Force Threshold", min_value=3, max_value=20, value=settings.BRUTE_FORCE_THRESHOLD
    )
    window_minutes = st.slider(
        "Time Window (Minutes)", min_value=5, max_value=60, value=settings.BRUTE_FORCE_WINDOW_MINUTES
    )
    user_enum_th = st.slider(
        "User Enum Threshold", min_value=2, max_value=10, value=settings.USER_ENUMERATION_THRESHOLD
    )

    st.markdown("---")
    st.subheader("📁 Quick Load Samples")
    sample_dir = Path(settings.SAMPLES_DIR)

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("OpenSSH Log", use_container_width=True):
            p = sample_dir / "openssh_sample.log"
            if p.exists():
                content = p.read_text(encoding="utf-8")
                recs, warns = parse_openssh_log(content, source_file="openssh_sample.log")
                evts, norm_warns = normalize_events(recs)
                st.session_state.events = evts
                st.session_state.warnings = warns + norm_warns
                # Run Detection
                eng = DetectionEngine(
                    brute_force_threshold=brute_force_th,
                    brute_force_window_minutes=window_minutes,
                    user_enumeration_threshold=user_enum_th,
                )
                st.session_state.alerts = eng.run_all_rules(evts)
                st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None
                st.session_state.report = None
                st.success(f"Loaded {len(evts)} OpenSSH events!")
                st.rerun()

    with col_s2:
        if st.button("JSON Sample", use_container_width=True):
            p = sample_dir / "auth_events.json"
            if p.exists():
                content = p.read_text(encoding="utf-8")
                recs, warns = parse_json_log(content, source_file="auth_events.json")
                evts, norm_warns = normalize_events(recs)
                st.session_state.events = evts
                st.session_state.warnings = warns + norm_warns
                eng = DetectionEngine(
                    brute_force_threshold=brute_force_th,
                    brute_force_window_minutes=window_minutes,
                    user_enumeration_threshold=user_enum_th,
                )
                st.session_state.alerts = eng.run_all_rules(evts)
                st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None
                st.session_state.report = None
                st.success(f"Loaded {len(evts)} JSON events!")
                st.rerun()

    if st.button("Clear Session", type="secondary", use_container_width=True):
        st.session_state.events = []
        st.session_state.alerts = []
        st.session_state.selected_alert = None
        st.session_state.report = None
        st.session_state.warnings = []
        st.rerun()

# Main Workspace Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📥 Ingestion & Telemetry",
    "🚨 Detection Engine & Alerts",
    "🤖 AI Investigation & Report",
    "📚 Knowledge Base Search (RAG)",
])

# ==========================================
# TAB 1: Ingestion & Telemetry
# ==========================================
with tab1:
    st.subheader("Security Log Upload & Normalization")
    uploaded_file = st.file_uploader(
        "Upload raw log file (.log, .txt, .csv, .json)",
        type=["log", "txt", "csv", "json"],
        help=f"File size must not exceed {settings.MAX_FILE_SIZE_MB}MB.",
    )

    if uploaded_file is not None:
        try:
            content_bytes = uploaded_file.read()
            validate_file_size(content_bytes, max_mb=settings.MAX_FILE_SIZE_MB)
            content_str = content_bytes.decode("utf-8", errors="replace")

            fname = uploaded_file.name.lower()
            if fname.endswith(".csv"):
                recs, warns = parse_csv_log(content_str, source_file=uploaded_file.name)
            elif fname.endswith(".json"):
                recs, warns = parse_json_log(content_str, source_file=uploaded_file.name)
            else:
                recs, warns = parse_openssh_log(content_str, source_file=uploaded_file.name)

            evts, norm_warns = normalize_events(recs)
            st.session_state.events = evts
            st.session_state.warnings = warns + norm_warns

            # Automatically run detection rules
            eng = DetectionEngine(
                brute_force_threshold=brute_force_th,
                brute_force_window_minutes=window_minutes,
                user_enumeration_threshold=user_enum_th,
            )
            st.session_state.alerts = eng.run_all_rules(evts)
            st.session_state.selected_alert = st.session_state.alerts[0] if st.session_state.alerts else None
            st.session_state.report = None
            st.success(f"Successfully normalized {len(evts)} events from {uploaded_file.name}!")
        except IngestionError as ie:
            st.error(f"Ingestion Error: {str(ie)}")
        except Exception as e:
            st.error(f"Unexpected parsing error: {str(e)}")

    # Display Warning Messages if any
    if st.session_state.warnings:
        with st.expander(f"⚠️ Ingestion Warnings ({len(st.session_state.warnings)})"):
            for w in st.session_state.warnings[:20]:
                st.write(f"- {w}")

    # Display Normalized Events Table
    if st.session_state.events:
        st.markdown("### Normalized Telemetry Grid")
        events_data = [
            {
                "Event ID": e.event_id,
                "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Type": e.event_type,
                "Outcome": e.outcome.value.upper(),
                "User": e.username or "—",
                "Source IP": e.source_ip or "—",
                "Message": e.message,
            }
            for e in st.session_state.events
        ]
        df_events = pd.DataFrame(events_data)

        # Filters
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            outcome_filter = st.multiselect(
                "Filter Outcome",
                options=["ALL", "SUCCESS", "FAILURE", "UNKNOWN"],
                default=["ALL"],
            )
        with f_col2:
            search_query = st.text_input("Search User or IP", "")

        df_filtered = df_events
        if "ALL" not in outcome_filter and outcome_filter:
            df_filtered = df_filtered[df_filtered["Outcome"].isin(outcome_filter)]
        if search_query:
            q = search_query.lower()
            df_filtered = df_filtered[
                df_filtered["User"].str.lower().str.contains(q, na=False)
                | df_filtered["Source IP"].str.lower().str.contains(q, na=False)
            ]

        st.dataframe(df_filtered, use_container_width=True, height=350)
    else:
        st.info("No logs loaded yet. Upload a log or click 'OpenSSH Log' in the sidebar to load the sample.")

# ==========================================
# TAB 2: Detection Engine & Alerts
# ==========================================
with tab2:
    st.subheader("Deterministic Detection Alerts")

    if st.session_state.events:
        # Metrics Row
        total_evts = len(st.session_state.events)
        total_alerts = len(st.session_state.alerts)
        crit_alerts = sum(1 for a in st.session_state.alerts if a.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH))
        unique_ips = len({e.source_ip for e in st.session_state.events if e.source_ip})

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(
                f'<div class="soc-metric-card"><div class="metric-title">Total Events</div><div class="metric-value">{total_evts}</div></div>',
                unsafe_allow_html=True,
            )
        with m2:
            st.markdown(
                f'<div class="soc-metric-card"><div class="metric-title">Detected Alerts</div><div class="metric-value" style="color: #f97316;">{total_alerts}</div></div>',
                unsafe_allow_html=True,
            )
        with m3:
            st.markdown(
                f'<div class="soc-metric-card"><div class="metric-title">High/Critical Alerts</div><div class="metric-value" style="color: #ef4444;">{crit_alerts}</div></div>',
                unsafe_allow_html=True,
            )
        with m4:
            st.markdown(
                f'<div class="soc-metric-card"><div class="metric-title">Unique Origin IPs</div><div class="metric-value" style="color: #38bdf8;">{unique_ips}</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        if st.session_state.alerts:
            st.write("Select an alert to inspect evidence or trigger an AI investigation:")

            for idx, alert in enumerate(st.session_state.alerts):
                badge_class = f"badge-{alert.severity.value.lower()}"
                with st.container():
                    st.markdown(
                        f"""
                    <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <span class="{badge_class}">{alert.severity.value}</span>
                                <strong style="font-size: 1.1rem; margin-left: 10px; color: #f8fafc;">{alert.rule_name}</strong>
                                <span style="color: #94a3b8; font-size: 0.85rem; margin-left: 8px;">({alert.rule_id})</span>
                            </div>
                            <div style="color: #94a3b8; font-size: 0.85rem;">
                                Alert ID: <code>{alert.alert_id}</code>
                            </div>
                        </div>
                        <p style="margin: 10px 0 6px 0; color: #cbd5e1;">{alert.description}</p>
                        <div style="font-size: 0.88rem; color: #94a3b8;">
                            <strong>Origin IP:</strong> <code>{alert.source_ip or 'N/A'}</code> | 
                            <strong>Target User:</strong> <code>{alert.affected_user or 'N/A'}</code> | 
                            <strong>Supporting Events:</strong> {len(alert.triggering_event_ids)} events |
                            <strong>MITRE:</strong> {', '.join(alert.mitre_candidates)}
                        </div>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                    c_act1, c_act2 = st.columns([1, 4])
                    with c_act1:
                        if st.button(f"⚡ Investigate with AI", key=f"inv_btn_{alert.alert_id}"):
                            st.session_state.selected_alert = alert
                            # Trigger investigation with RAG
                            with st.spinner(f"Retrieving MITRE guidance and analyzing {alert.alert_id} with AI Analyst..."):
                                client = get_llm_client(force_mock=use_mock)
                                gen = InvestigationGenerator(llm_client=client)
                                report = gen.investigate_alert(alert, st.session_state.events)
                                st.session_state.report = report
                            st.success(f"Investigation completed for {alert.alert_id}!")
                            st.rerun()
                    with c_act2:
                        with st.expander(f"Inspect Supporting Event IDs ({len(alert.triggering_event_ids)})"):
                            st.code(", ".join(alert.triggering_event_ids), language="text")
        else:
            st.success("No suspicious patterns or rule violations detected in the loaded dataset.")
    else:
        st.info("Load logs in Tab 1 to run the detection engine.")

# ==========================================
# TAB 3: AI Investigation & Report
# ==========================================
with tab3:
    st.subheader("Tier-3 Incident Investigation & Findings")

    if st.session_state.report is not None:
        rep = st.session_state.report

        # Executive Banner
        badge_cls = f"badge-{rep.severity.value.lower()}"
        st.markdown(
            f"""
        <div class="report-box">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <span class="{badge_cls}">{rep.severity.value}</span>
                    <h2 style="margin: 8px 0 4px 0; color: #38bdf8;">{rep.title}</h2>
                    <span style="color: #94a3b8; font-size: 0.9rem;">
                        <strong>Case:</strong> <code>{rep.case_id}</code> | 
                        <strong>Alert:</strong> <code>{rep.alert_id}</code> | 
                        <strong>Incident Type:</strong> {rep.incident_type}
                    </span>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 0.8rem; color: #94a3b8; text-transform: uppercase;">Confidence Score</div>
                    <div style="font-size: 1.8rem; font-weight: 700; color: #22c55e;">{rep.confidence_score * 100:.0f}%</div>
                    <div style="font-size: 0.75rem; color: #64748b;">Ground-truth corroborated</div>
                </div>
            </div>
            <p style="margin-top: 14px; color: #e2e8f0; line-height: 1.5;">{rep.summary}</p>
            <div style="background: rgba(15, 23, 42, 0.6); padding: 10px; border-radius: 6px; margin-top: 10px; font-size: 0.88rem; color: #cbd5e1;">
                <strong>Severity Justification:</strong> {rep.severity_rationale}
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Observed Facts vs Inferred Conclusions
        c_facts, c_inferences = st.columns(2)
        with c_facts:
            st.markdown("### 🔍 Directly Observed Facts")
            st.caption("Verifiable telemetry points strictly extracted from log records:")
            for fact in rep.observed_facts:
                st.markdown(f"- ✅ **{fact}**")

        with c_inferences:
            st.markdown("### 💡 Inferred Conclusions")
            st.caption("Analytical hypotheses and deductive reasoning derived from facts:")
            for inf in rep.inferred_conclusions:
                st.markdown(f"- 🔮 {inf}")

        st.markdown("---")

        # MITRE ATT&CK Mapping
        st.markdown("### 🛡️ MITRE ATT&CK Alignment")
        if rep.mitre_techniques:
            mitre_data = [
                {
                    "Technique ID": m.technique_id,
                    "Technique Name": m.technique_name,
                    "Evidence Rationale": m.evidence,
                }
                for m in rep.mitre_techniques
            ]
            st.table(pd.DataFrame(mitre_data))
        else:
            st.write("No direct MITRE ATT&CK techniques mapped.")

        # Grounded Cybersecurity Knowledge & Citations (RAG)
        if rep.retrieved_knowledge:
            st.markdown("### 📚 Grounded Cybersecurity Knowledge & Citations (RAG)")
            st.caption("Evidence retrieved from local FAISS vector index during investigation:")
            for k in rep.retrieved_knowledge:
                score = k.get("similarity_score", 0.0)
                with st.expander(f"📖 {k.get('title', 'Unknown')} (Relevance: {score * 100:.1f}%)"):
                    st.markdown(f"**Citation:** `{k.get('citation', '')}`")
                    st.markdown(f"**Tactics / Category:** `{', '.join(k.get('tactics', []))}`")
                    st.markdown(f"```text\n{k.get('text', '')}\n```")

        st.markdown("---")

        # Alternative Explanations & Limitations
        c_alt, c_lim = st.columns(2)
        with c_alt:
            st.markdown("### 🔄 Benign Alternative Explanations")
            for alt in rep.alternative_explanations:
                st.markdown(f"- ⚠️ {alt}")
        with c_lim:
            st.markdown("### ⚠️ Investigation Limitations")
            for lim in rep.investigation_limitations:
                st.markdown(f"- 📋 {lim}")

        st.markdown("---")

        # Recommended Next Steps
        st.markdown("### 🚀 Actionable Remediation & Next Steps")
        for idx, rec in enumerate(rep.recommended_actions, start=1):
            st.markdown(f"**{idx}.** {rec}")

        st.markdown("---")

        # Human Review & Export Section
        st.markdown("### ✍️ Analyst Review & Sign-Off")
        r_col1, r_col2 = st.columns([2, 2])
        with r_col1:
            new_status = st.selectbox(
                "Analyst Sign-off Status",
                [s.value for s in ReviewStatus],
                index=[s.value for s in ReviewStatus].index(rep.analyst_review_status.value),
            )
            if new_status != rep.analyst_review_status.value:
                rep.analyst_review_status = ReviewStatus(new_status)
                st.success(f"Review status updated to {new_status}!")

        with r_col2:
            st.markdown("**Export Case Report**")
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                md_text = export_report_to_markdown(rep)
                st.download_button(
                    label="📄 Download Markdown",
                    data=md_text,
                    file_name=f"{rep.case_id}_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with exp_col2:
                js_text = export_report_to_json(rep)
                st.download_button(
                    label="💾 Download JSON",
                    data=js_text,
                    file_name=f"{rep.case_id}_report.json",
                    mime="application/json",
                    use_container_width=True,
                )

    else:
        st.info("No investigation run yet. Go to **Tab 2 (Detection Engine & Alerts)** and click **⚡ Investigate with AI** on any detected alert.")

# ==========================================
# TAB 4: Knowledge Base Search (RAG)
# ==========================================
with tab4:
    st.subheader("Interactive MITRE ATT&CK & Incident Response Vector Search")
    st.markdown(
        "Directly query the indexed cybersecurity knowledge base (FAISS + sentence-transformers). "
        "Search for attack techniques, detection heuristics, and containment playbooks."
    )

    q_col1, q_col2, q_col3 = st.columns([3, 1, 1])
    with q_col1:
        rag_search_query = st.text_input(
            "Semantic Query",
            value="SSH password guessing brute force",
            placeholder="e.g. password spraying, privilege escalation, SSH lateral movement...",
        )
    with q_col2:
        source_filter_opt = st.selectbox(
            "Source Filter",
            options=["All Sources", "mitre_attack", "incident_playbook"],
        )
    with q_col3:
        top_k_opt = st.slider("Max Results", min_value=1, max_value=8, value=4)

    if st.button("🔍 Search Knowledge Base", type="primary", use_container_width=True):
        src_filt = None if source_filter_opt == "All Sources" else source_filter_opt
        with st.spinner("Searching FAISS vector index..."):
            retriever = RAGRetriever()
            search_results = retriever.retrieve(
                query=rag_search_query,
                top_k=top_k_opt,
                score_threshold=0.15,
                source_filter=src_filt,
            )

        if search_results:
            st.success(f"Found {len(search_results)} relevant knowledge chunks!")
            for idx, res in enumerate(search_results, start=1):
                badge_type = "MITRE ATT&CK" if res.source_type == "mitre_attack" else "NIST Playbook"
                with st.expander(f"#{idx} [{badge_type}] {res.title} (Score: {res.similarity_score * 100:.1f}%)", expanded=(idx == 1)):
                    st.markdown(f"**Citation:** `{res.citation}`")
                    if res.url:
                        st.markdown(f"**Reference Link:** [{res.url}]({res.url})")
                    if res.tactics:
                        st.markdown(f"**Tactics/Category:** `{', '.join(res.tactics)}`")
                    st.markdown("---")
                    st.markdown(f"```text\n{res.text}\n```")
        else:
            st.warning("No knowledge chunks exceeded the relevance threshold for this query.")
