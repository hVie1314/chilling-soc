"""
SOC AI Triage System — Streamlit Web Interface

Provides:
  • Text area to paste raw security logs
  • "Analyze" button → calls POST /analyze
  • Parsed JSON result display with severity badge
  • Similar past cases panel (RAG hits)
  • Feedback form → calls POST /feedback
"""

from __future__ import annotations

import os

import httpx
import streamlit as st

# ───────────────────────── Configuration ─────────────────────────

API_URL: str = os.getenv("API_BACKEND_URL", "http://localhost:8080")
REQUEST_TIMEOUT: float = 120.0  # LLM inference can be slow

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

    /* ── Verdict badges ─────────────────────────────────── */
    .badge-fp {
        display: inline-block;
        background: linear-gradient(135deg, #065f46, #047857);
        color: #d1fae5;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }
    .badge-tp {
        display: inline-block;
        background: linear-gradient(135deg, #92400e, #b45309);
        color: #fef3c7;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
    }
    .badge-incident {
        display: inline-block;
        background: linear-gradient(135deg, #991b1b, #dc2626);
        color: #fee2e2;
        padding: 6px 18px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.5px;
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
    </style>
    """,
    unsafe_allow_html=True,
)

# ───────────────────────── State Init ────────────────────────────

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "analyzed_log" not in st.session_state:
    st.session_state.analyzed_log = ""
if "similar_cases" not in st.session_state:
    st.session_state.similar_cases = []

# ───────────────────────── Sidebar ───────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ System Info")
    st.caption(f"Backend: `{API_URL}`")

    # Quick health check
    try:
        resp = httpx.get(f"{API_URL}/health", timeout=5)
        if resp.status_code == 200:
            st.success("API Backend: **Online**", icon="✅")
        else:
            st.warning(f"API Backend: HTTP {resp.status_code}", icon="⚠️")
    except httpx.ConnectError:
        st.error("API Backend: **Unreachable**", icon="🔴")
    except Exception as e:
        st.error(f"Health check error: {e}", icon="🔴")

    st.divider()
    st.markdown(
        "**How it works**\n\n"
        "1. Paste a raw log below\n"
        "2. AI triages it as **FP**, **TP**, or **Incident**\n"
        "3. Review & correct the verdict\n"
        "4. Your feedback trains future analysis"
    )

# ───────────────────────── Main Content ──────────────────────────

st.markdown('<p class="main-header">🛡️ SOC AI Triage</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">AI-powered security log triage with analyst feedback loop</p>',
    unsafe_allow_html=True,
)

# ── Log Input ────────────────────────────────────────────────────

raw_log = st.text_area(
    "Paste raw security log",
    height=180,
    placeholder=(
        "Example: Aug 22 14:33:12 fw01 kernel: "
        "DROP IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.0.5 "
        'PROTO=TCP DPT=443 ...\n\n'
        "Or paste a Suricata / Snort / SIEM JSON alert …"
    ),
)

analyze_clicked = st.button("🔍  Analyze", type="primary", use_container_width=True)

# ── Analyze Action ───────────────────────────────────────────────

if analyze_clicked:
    if not raw_log.strip():
        st.warning("Please paste a log entry before analyzing.", icon="⚠️")
    else:
        with st.spinner("Embedding log and querying LLM …"):
            try:
                resp = httpx.post(
                    f"{API_URL}/analyze",
                    json={"raw_log": raw_log.strip()},
                    timeout=REQUEST_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
                st.session_state.analysis_result = data
                st.session_state.analyzed_log = raw_log.strip()
                st.session_state.similar_cases = data.get("similar_cases", [])
            except httpx.HTTPStatusError as e:
                st.error(f"Backend error (HTTP {e.response.status_code}): {e.response.text}", icon="🚨")
            except httpx.ConnectError:
                st.error("Cannot reach the API backend. Is it running?", icon="🔴")
            except Exception as e:
                st.error(f"Unexpected error: {e}", icon="🚨")

# ── Results Display ──────────────────────────────────────────────

result = st.session_state.analysis_result

if result:
    st.divider()
    st.subheader("Triage Result")

    verdict = result.get("result", "?")
    reason = result.get("reason", "—")

    badge_class = {
        "FP": "badge-fp",
        "TP": "badge-tp",
        "Incident": "badge-incident",
    }.get(verdict, "badge-tp")

    col1, col2 = st.columns([1, 3])
    with col1:
        st.markdown(f'<span class="{badge_class}">{verdict}</span>', unsafe_allow_html=True)
    with col2:
        st.markdown(f"**Reason:** {reason}")

    # ── Similar Cases (RAG) ──────────────────────────────────────
    cases = st.session_state.similar_cases
    if cases:
        st.divider()
        st.subheader("📚 Similar Past Cases")
        for i, case in enumerate(cases, 1):
            with st.expander(f"Case {i}  —  {case.get('label', '?')}  (score: {case.get('score', '?')})"):
                st.code(case.get("raw_log", "—"), language="text")
                st.caption(f"**Analyst comment:** {case.get('analyst_comment', '—')}")

    # ── Feedback Form ────────────────────────────────────────────
    st.divider()
    st.subheader("📝 Analyst Feedback")
    st.caption("Correct or confirm the verdict to improve future triage accuracy.")

    with st.form("feedback_form"):
        label_options = ["FP", "TP", "Incident"]
        default_idx = label_options.index(verdict) if verdict in label_options else 0

        fb_label = st.selectbox(
            "Correct / Confirm Label",
            options=label_options,
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
                        st.success(
                            f"Feedback saved! Point ID: `{fb_data.get('point_id', '?')}`",
                            icon="✅",
                        )
                    except httpx.HTTPStatusError as e:
                        st.error(
                            f"Backend error (HTTP {e.response.status_code}): {e.response.text}",
                            icon="🚨",
                        )
                    except Exception as e:
                        st.error(f"Failed to store feedback: {e}", icon="🚨")
