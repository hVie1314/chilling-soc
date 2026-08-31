"""
SOC AI Triage System — Streamlit Web Interface v3.0

Professional 3-tab cybersecurity dashboard:
  • Tab 1 — 🎯 Triage Hub:  Multi-event analysis, verdict display, analyst feedback
  • Tab 2 — 📊 Analytics:   Placeholder stats & charts
  • Tab 3 — ⚙️ System Config: Environment settings & health check

Uses unified labels: TruePositive | FalsePositive | Benign | Suspicious
"""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import streamlit as st

# ───────────────────────── Configuration ─────────────────────────

API_URL: str = os.getenv("API_BACKEND_URL", "http://localhost:8080")
REQUEST_TIMEOUT: float = 120.0  # LLM inference can be slow

UNIFIED_LABELS = ["TruePositive", "FalsePositive", "Benign", "Suspicious"]

# ───────────────────────── Page Setup ────────────────────────────

st.set_page_config(
    page_title="SOC AI Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ───────────────────────── Custom CSS ────────────────────────────

st.markdown(
    """
    <style>
    /* ── Global ─────────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* ── Verdict badges (unified labels) ───────────────── */
    .badge-truepositive {
        display: inline-block;
        background: linear-gradient(135deg, #991b1b, #dc2626);
        color: #fee2e2;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }
    .badge-falsepositive {
        display: inline-block;
        background: linear-gradient(135deg, #065f46, #047857);
        color: #d1fae5;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }
    .badge-benign {
        display: inline-block;
        background: linear-gradient(135deg, #1e40af, #3b82f6);
        color: #dbeafe;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }
    .badge-suspicious {
        display: inline-block;
        background: linear-gradient(135deg, #92400e, #b45309);
        color: #fef3c7;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }

    /* ── Trust score bar ───────────────────────────────── */
    .trust-bar {
        display: inline-block;
        font-size: 0.85rem;
        opacity: 0.85;
        margin-left: 8px;
    }

    /* ── Similar-case card ──────────────────────────────── */
    .rag-card {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 12px;
    }
    .rag-card .score {
        float: right;
        font-size: 0.85rem;
        opacity: 0.6;
    }

    /* ── Header ─────────────────────────────────────────── */
    .main-header {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .sub-header {
        font-size: 1rem;
        opacity: 0.6;
        margin-bottom: 24px;
    }

    /* ── Stat card ──────────────────────────────────────── */
    .stat-card {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.10);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
    }
    .stat-card h3 {
        margin: 0;
        font-size: 2.2rem;
        font-weight: 700;
    }
    .stat-card p {
        margin: 4px 0 0 0;
        opacity: 0.6;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ───────────────────────── State Init ────────────────────────────

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "analyzed_log" not in st.session_state:
    st.session_state.analyzed_log = ""
if "analyzed_events" not in st.session_state:
    st.session_state.analyzed_events = []
if "similar_cases" not in st.session_state:
    st.session_state.similar_cases = []
if "alert_id" not in st.session_state:
    st.session_state.alert_id = "default-alert"

# Analytics session counters (in-memory placeholder)
if "stats_total" not in st.session_state:
    st.session_state.stats_total = 0
if "stats_verdicts" not in st.session_state:
    st.session_state.stats_verdicts = {label: 0 for label in UNIFIED_LABELS}

# System config
if "cfg_webhook_url" not in st.session_state:
    st.session_state.cfg_webhook_url = ""
if "cfg_soar_api_url" not in st.session_state:
    st.session_state.cfg_soar_api_url = ""

# ───────────────────────── Sidebar ───────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ System Info")
    st.caption(f"Backend: `{API_URL}`")

    # Quick health check
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=5)
        if resp.status_code == 200:
            health_data = resp.json()
            st.success("API Backend: **Online**", icon="✅")

            qdrant_status = health_data.get("qdrant", "unknown")
            llm_status = health_data.get("llm", "unknown")
            sqlite_status = health_data.get("sqlite", "unknown")

            st.caption(f"Qdrant: `{qdrant_status}` · LLM: `{llm_status}` · SQLite: `{sqlite_status}`")
        else:
            st.warning(f"API Backend: HTTP {resp.status_code}", icon="⚠️")
    except httpx.ConnectError:
        st.error("API Backend: **Unreachable**", icon="🔴")
    except Exception as e:
        st.error(f"Health check error: {e}", icon="🔴")

    st.divider()
    st.markdown(
        "**How it works**\n\n"
        "1. Paste raw log event(s) (one per line)\n"
        "2. AI triages as **TruePositive**, **FalsePositive**, **Benign**, or **Suspicious**\n"
        "3. Review & correct the verdict\n"
        "4. Your feedback trains future analysis"
    )

# ───────────────────────── Helpers ───────────────────────────────

def _trust_stars(score: int, max_score: int = 5) -> str:
    """Render trust score as filled/empty star icons."""
    return "★" * score + "☆" * (max_score - score)


def _badge_class(verdict: str) -> str:
    """Return CSS class for a unified verdict label."""
    return {
        "TruePositive": "badge-truepositive",
        "FalsePositive": "badge-falsepositive",
        "Benign": "badge-benign",
        "Suspicious": "badge-suspicious",
    }.get(verdict, "badge-suspicious")


# ───────────────────────── Main Header ───────────────────────────

st.markdown('<p class="main-header">🛡️ SOC AI Triage</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">AI-powered security log triage with analyst feedback loop · v3.0</p>',
    unsafe_allow_html=True,
)

# ───────────────────────── Tabs ──────────────────────────────────

tab_triage, tab_analytics, tab_config = st.tabs([
    "🎯 Triage Hub",
    "📊 Analytics & Stats",
    "⚙️ System Config",
])

# ═══════════════════════════════════════════════════════════════
# TAB 1: TRIAGE HUB
# ═══════════════════════════════════════════════════════════════
with tab_triage:

    # ── Alert ID & Log Input ─────────────────────────────────────
    col_id, col_spacer = st.columns([2, 3])
    with col_id:
        alert_id_input = st.text_input(
            "Alert ID",
            value=st.session_state.alert_id,
            placeholder="e.g. ALERT-2026-08-001",
            help="Identifier for this alert group. Used for state tracking and webhook correlation.",
        )

    raw_log = st.text_area(
        "Paste raw security event log(s) — one event per line",
        height=180,
        placeholder=(
            "Example:\n"
            "Aug 22 14:33:12 fw01 kernel: DROP IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.0.5 PROTO=TCP DPT=443 ...\n"
            "Aug 22 14:33:15 fw01 kernel: ACCEPT IN=eth1 OUT= SRC=10.0.0.10 DST=10.0.0.5 PROTO=TCP DPT=22 ...\n\n"
            "Or paste Suricata / Snort / SIEM JSON alerts (one per line)"
        ),
    )

    analyze_clicked = st.button("🔍  Analyze", type="primary", use_container_width=True)

    # ── Analyze Action ───────────────────────────────────────────
    if analyze_clicked:
        if not raw_log.strip():
            st.warning("Please paste at least one log entry before analyzing.", icon="⚠️")
        else:
            events = [line.strip() for line in raw_log.strip().split("\n") if line.strip()]
            with st.spinner(f"Embedding {len(events)} event(s) and querying LLM …"):
                try:
                    resp = httpx.post(
                        f"{API_URL}/analyze",
                        json={
                            "alert_id": alert_id_input or "default-alert",
                            "events": events,
                        },
                        timeout=REQUEST_TIMEOUT,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    st.session_state.analysis_result = data
                    st.session_state.analyzed_log = raw_log.strip()
                    st.session_state.analyzed_events = events
                    st.session_state.alert_id = alert_id_input or "default-alert"
                    st.session_state.similar_cases = data.get("similar_cases", [])

                    # Update analytics counters
                    verdict = data.get("result", "")
                    st.session_state.stats_total += 1
                    if verdict in st.session_state.stats_verdicts:
                        st.session_state.stats_verdicts[verdict] += 1

                except httpx.HTTPStatusError as e:
                    st.error(f"Backend error (HTTP {e.response.status_code}): {e.response.text}", icon="🚨")
                except httpx.ConnectError:
                    st.error("Cannot reach the API backend. Is it running?", icon="🔴")
                except Exception as e:
                    st.error(f"Unexpected error: {e}", icon="🚨")

    # ── Results Display ──────────────────────────────────────────
    result = st.session_state.analysis_result

    if result:
        st.divider()
        st.subheader("Triage Result")

        verdict = result.get("result", "?")
        reason = result.get("reason", "—")

        col1, col2 = st.columns([1, 3])
        with col1:
            st.markdown(
                f'<span class="{_badge_class(verdict)}">{verdict}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(f"**Reason:** {reason}")

        # Event count info
        event_count = len(st.session_state.analyzed_events)
        if event_count > 0:
            st.caption(f"📋 Analyzed {event_count} event(s) · Alert ID: `{st.session_state.alert_id}`")

        # ── Raw JSON ─────────────────────────────────────────────
        with st.expander("🔧 Raw JSON Response"):
            st.json(result)

        # ── Similar Cases (RAG) ──────────────────────────────────
        cases = st.session_state.similar_cases
        if cases:
            st.divider()
            st.subheader("📚 Similar Past Cases")
            for i, case in enumerate(cases, 1):
                trust = case.get("trust_score", 1)
                trust_display = _trust_stars(trust)
                label = case.get("label", "?")
                score = case.get("score", "?")
                with st.expander(
                    f"Case {i}  —  {label}  (score: {score})  |  Trust: {trust_display}"
                ):
                    st.code(case.get("raw_log", "—"), language="text")
                    st.caption(
                        f"**Trust Score:** {trust}/5 {trust_display}\n\n"
                        f"**Analyst comment:** {case.get('comment', '—')}"
                    )

        # ── Feedback Form ────────────────────────────────────────
        st.divider()
        st.subheader("📝 Analyst Feedback")
        st.caption("Correct or confirm the verdict to improve future triage accuracy.")

        with st.form("feedback_form"):
            default_idx = UNIFIED_LABELS.index(verdict) if verdict in UNIFIED_LABELS else 0

            fb_label = st.selectbox(
                "Correct / Confirm Label",
                options=UNIFIED_LABELS,
                index=default_idx,
            )
            fb_comment = st.text_input(
                "Analyst Comment",
                placeholder="e.g. Known scanner IP, expected behaviour during maintenance …",
            )
            submitted = st.form_submit_button(
                "💾  Save to Knowledge Base",
                type="primary",
                use_container_width=True,
            )

            if submitted:
                if not st.session_state.analyzed_log:
                    st.warning("No analyzed log to attach feedback to.", icon="⚠️")
                else:
                    with st.spinner("Storing feedback …"):
                        try:
                            fb_resp = httpx.post(
                                f"{API_URL}/feedback",
                                json={
                                    "raw_log": st.session_state.analyzed_log,
                                    "label": fb_label,
                                    "analyst_comment": fb_comment,
                                },
                                timeout=30,
                            )
                            fb_resp.raise_for_status()
                            fb_data = fb_resp.json()

                            action = fb_data.get("action", "stored")
                            trust = fb_data.get("trust_score", 1)
                            point_id = fb_data.get("point_id", "?")

                            action_labels = {
                                "inserted": "🆕 New entry created",
                                "reinforced": "🔄 Existing entry reinforced",
                                "corrected": "⚠️ Label corrected (trust reset)",
                            }
                            action_label = action_labels.get(action, action)

                            st.success(
                                f"{action_label}  |  Trust: {_trust_stars(trust)} ({trust}/5)  |  "
                                f"Point ID: `{point_id}`",
                                icon="✅",
                            )
                        except httpx.HTTPStatusError as e:
                            st.error(
                                f"Backend error (HTTP {e.response.status_code}): {e.response.text}",
                                icon="🚨",
                            )
                        except Exception as e:
                            st.error(f"Failed to store feedback: {e}", icon="🚨")


# ═══════════════════════════════════════════════════════════════
# TAB 2: ANALYTICS & STATS
# ═══════════════════════════════════════════════════════════════
with tab_analytics:
    st.subheader("📊 Analytics & Stats")
    st.caption("Session-level analytics — counters reset on page reload. "
               "Production deployment should query SQLite/Qdrant for persistent stats.")

    st.divider()

    # ── Metric cards ─────────────────────────────────────────────
    mcol1, mcol2, mcol3, mcol4, mcol5 = st.columns(5)

    total = st.session_state.stats_total
    verdicts = st.session_state.stats_verdicts

    with mcol1:
        st.metric("Total Analyzed", total)
    with mcol2:
        st.metric("TruePositive", verdicts.get("TruePositive", 0))
    with mcol3:
        st.metric("FalsePositive", verdicts.get("FalsePositive", 0))
    with mcol4:
        st.metric("Benign", verdicts.get("Benign", 0))
    with mcol5:
        st.metric("Suspicious", verdicts.get("Suspicious", 0))

    st.divider()

    # ── Verdict distribution chart ───────────────────────────────
    st.subheader("Verdict Distribution")

    if total > 0:
        import pandas as pd

        chart_data = pd.DataFrame({
            "Verdict": list(verdicts.keys()),
            "Count": list(verdicts.values()),
        })
        st.bar_chart(chart_data, x="Verdict", y="Count", use_container_width=True)
    else:
        st.info("No alerts analyzed yet in this session. Go to the **Triage Hub** tab to get started.", icon="ℹ️")

    st.divider()

    # ── Ratio display ────────────────────────────────────────────
    st.subheader("Detection Ratios")

    if total > 0:
        tp_count = verdicts.get("TruePositive", 0) + verdicts.get("Suspicious", 0)
        fp_count = verdicts.get("FalsePositive", 0) + verdicts.get("Benign", 0)

        rcol1, rcol2, rcol3 = st.columns(3)
        with rcol1:
            tp_pct = (tp_count / total * 100) if total > 0 else 0
            st.metric("Malicious Rate", f"{tp_pct:.1f}%", help="TruePositive + Suspicious")
        with rcol2:
            fp_pct = (fp_count / total * 100) if total > 0 else 0
            st.metric("Benign Rate", f"{fp_pct:.1f}%", help="FalsePositive + Benign")
        with rcol3:
            ratio_str = f"{tp_count}:{fp_count}"
            st.metric("TP:FP Ratio", ratio_str)
    else:
        st.caption("Ratios will appear after the first analysis.")


# ═══════════════════════════════════════════════════════════════
# TAB 3: SYSTEM CONFIG
# ═══════════════════════════════════════════════════════════════
with tab_config:
    st.subheader("⚙️ System Configuration")
    st.caption("Configure integration endpoints. Changes are stored in session only.")

    st.divider()

    # ── Current backend info ─────────────────────────────────────
    st.markdown("### Backend Connection")
    st.code(f"API_BACKEND_URL = {API_URL}", language="text")

    # ── Health check detail ──────────────────────────────────────
    st.markdown("### Service Health")
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=5)
        if resp.status_code == 200:
            health_data = resp.json()
            hcol1, hcol2, hcol3, hcol4 = st.columns(4)
            with hcol1:
                qs = health_data.get("qdrant", "unknown")
                if qs == "connected":
                    st.success("Qdrant: Connected", icon="✅")
                else:
                    st.error(f"Qdrant: {qs}", icon="🔴")
            with hcol2:
                ls = health_data.get("llm", "unknown")
                if ls == "connected":
                    st.success("LLM: Connected", icon="✅")
                else:
                    st.error(f"LLM: {ls}", icon="🔴")
            with hcol3:
                ss = health_data.get("sqlite", "unknown")
                if ss == "connected":
                    cases_count = health_data.get("sqlite_cases_count", "?")
                    st.success(f"SQLite: {cases_count} cases", icon="✅")
                else:
                    st.error(f"SQLite: {ss}", icon="🔴")
            with hcol4:
                llm_models = health_data.get("llm_models", [])
                if llm_models:
                    st.info(f"Model: {llm_models[0]}", icon="🤖")
                else:
                    st.caption("Model: unknown")
        else:
            st.warning(f"Health check returned HTTP {resp.status_code}")
    except Exception as e:
        st.error(f"Cannot reach backend: {e}", icon="🔴")

    st.divider()

    # ── Integration endpoints ────────────────────────────────────
    st.markdown("### Integration Endpoints")

    with st.form("config_form"):
        webhook_url = st.text_input(
            "Webhook URL (Case Management)",
            value=st.session_state.cfg_webhook_url,
            placeholder="https://your-case-management.example.com/webhook",
            help="URL where the system sends case management updates.",
        )
        soar_api_url = st.text_input(
            "SOAR API URL",
            value=st.session_state.cfg_soar_api_url,
            placeholder="https://your-soar.example.com/api/v1",
            help="SOAR platform API endpoint for auto-close actions.",
        )

        config_submitted = st.form_submit_button(
            "💾  Save Configuration",
            type="primary",
            use_container_width=True,
        )

        if config_submitted:
            st.session_state.cfg_webhook_url = webhook_url
            st.session_state.cfg_soar_api_url = soar_api_url
            st.success("Configuration saved to session.", icon="✅")
            st.caption("Note: These values are stored in the browser session only and will reset on page reload.")
