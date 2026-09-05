"""
SOC AI Triage System — Streamlit Web Interface v4.0

Implements io-routing-spec.md v1.0.0 in full:
  • Tab 1 — 🎯 Triage Hub:    Multi-event analysis, verdict display (with ActionReceipt banners),
                               and analyst feedback submission.
  • Tab 2 — 📊 Analytics:     Session-level verdict counters and distribution chart.
  • Tab 3 — ⚙️ System Config:  Persistent I/O routing matrix (source × destination toggles),
                               secure destination credentials synced via PUT /config.

Uses unified labels: TruePositive | FalsePositive | Benign | Suspicious
Input source declared: "web_ui"
"""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import streamlit as st

# ───────────────────────── Configuration ─────────────────────────

API_URL: str = os.getenv("API_BACKEND_URL", "http://localhost:8080")
REQUEST_TIMEOUT: float = 120.0  # LLM inference can be slow
CONFIG_TIMEOUT: float = 10.0

UNIFIED_LABELS = ["TruePositive", "FalsePositive", "Benign", "Suspicious"]
AUTH_TYPES = ["none", "bearer", "api_key", "basic"]

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

    /* ── Routing policy card ────────────────────────────── */
    .routing-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.10);
        border-radius: 16px;
        padding: 20px 24px;
        margin-bottom: 8px;
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
if "actions_dispatched" not in st.session_state:
    st.session_state.actions_dispatched = []
if "alert_id" not in st.session_state:
    st.session_state.alert_id = "default-alert"

# Analytics session counters (in-memory placeholder)
if "stats_total" not in st.session_state:
    st.session_state.stats_total = 0
if "stats_verdicts" not in st.session_state:
    st.session_state.stats_verdicts = {label: 0 for label in UNIFIED_LABELS}

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
        "4. Your feedback trains future analysis\n"
        "5. Configure routing policies in **System Config**"
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


def _fetch_config() -> dict:
    """
    Load SystemSettings from the backend GET /config endpoint.
    Returns an empty dict on failure; the UI will render defaults.
    """
    try:
        resp = httpx.get(f"{API_URL}/config", timeout=CONFIG_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        st.warning(f"Could not load config from backend: {e}", icon="⚠️")
    return {}


def _render_action_receipts(actions: list[dict]) -> None:
    """
    Render the actions_dispatched list from an AnalyzeResponse.
    Shows distinct banners per destination and status.
    """
    if not actions:
        return

    st.divider()
    st.subheader("🚀 Dispatch Actions")

    for act in actions:
        dest = act.get("destination", "unknown")
        act_status = act.get("status", "unknown")
        details = act.get("details", "")
        error = act.get("error", "")
        http_code = act.get("http_status")
        ts = act.get("timestamp", "")

        dest_label = {
            "case_management": "📋 Case Management",
            "soar_edge": "⚡ SOAR Edge",
            "all": "🌐 All Systems",
        }.get(dest, f"📡 {dest}")

        if act_status == "success":
            code_info = f" (HTTP {http_code})" if http_code else ""
            msg = f"{dest_label} → **Dispatched successfully**{code_info}"
            if details:
                msg += f"\n\n> {details}"
            st.success(msg, icon="✅")

        elif act_status == "skipped":
            msg = f"{dest_label} → **Skipped**: {details or 'No URL configured'}"
            st.info(msg, icon="ℹ️")

        elif act_status == "dry_run_skipped":
            st.warning(
                f"**Dry-Run Mode Active** — {details or 'No external systems were contacted.'}",
                icon="🔒",
            )

        elif act_status == "failed":
            code_info = f" (HTTP {http_code})" if http_code else ""
            msg = f"{dest_label} → **Dispatch FAILED**{code_info}"
            if error:
                msg += f"\n\n> Error: `{error}`"
            st.error(msg, icon="🚨")

        else:
            st.caption(f"{dest_label} → status: `{act_status}`  |  {ts[:19]}")


# ───────────────────────── Main Header ───────────────────────────

st.markdown('<p class="main-header">🛡️ SOC AI Triage</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">AI-powered security log triage with analyst feedback loop · v4.0</p>',
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
                            # Spec §4.1: Web UI must declare its source
                            "source": "web_ui",
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
                    # Spec §4.1: Capture actions_dispatched for receipt rendering
                    st.session_state.actions_dispatched = data.get("actions_dispatched", [])

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

        # ── Action Receipts (Spec §4.1) ──────────────────────────
        _render_action_receipts(st.session_state.actions_dispatched)

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
# Implements io-routing-spec.md §6 in full.
# Settings are PERSISTED to backend via PUT /config (not session-only).
# ═══════════════════════════════════════════════════════════════
with tab_config:
    st.subheader("⚙️ System Configuration")
    st.caption(
        "Manage I/O routing policies and integration credentials. "
        "Changes are persisted to the backend SQLite database — they survive page reloads and container restarts."
    )

    # ── Service Health ───────────────────────────────────────────
    st.markdown("### 🔌 Service Health")
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

    # ── Load current config from backend ────────────────────────
    # We load once per render cycle. The form will pre-populate from this.
    current_cfg = _fetch_config()

    # Deep-read helper with safe nested defaults
    def _cfg(path: str, default=None):
        """Navigate a dotted path into current_cfg dict safely."""
        parts = path.split(".")
        node = current_cfg
        for p in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(p, default)
            if node is None:
                return default
        return node

    # ── Main Configuration Form ──────────────────────────────────
    with st.form("config_form"):

        # ── Section 1: I/O Routing Matrix (Spec §6, item 1) ─────
        st.markdown("### 🔀 I/O Routing Matrix")
        st.caption(
            "Define which downstream systems are activated per **input source** and **AI verdict**. "
            "Human-in-the-loop safety: web_ui pushes are opt-in by default."
        )

        routing_col1, routing_col2 = st.columns(2)

        with routing_col1:
            st.markdown(
                '<div class="routing-card">'
                '<strong>🌐 Web UI Source Rules</strong><br>'
                '<small>Applies when an analyst manually submits logs via this interface.</small>'
                '</div>',
                unsafe_allow_html=True,
            )
            web_enable_case_push = st.checkbox(
                "📋 Push **TruePositive / Suspicious** to Case Management",
                value=bool(_cfg("routing.web_source.enable_case_mgmt_push", False)),
                help="When enabled, TruePositive and Suspicious verdicts from the Web UI will automatically POST to the Case Management webhook.",
                key="web_case_push",
            )
            web_enable_soar_close = st.checkbox(
                "⚡ Auto-close **FalsePositive / Benign** in SOAR",
                value=bool(_cfg("routing.web_source.enable_soar_autoclose", False)),
                help="When enabled, FalsePositive and Benign verdicts from the Web UI will trigger the SOAR auto-close API. Use with caution.",
                key="web_soar_close",
            )

        with routing_col2:
            st.markdown(
                '<div class="routing-card">'
                '<strong>🤖 SIEM / API Stream Rules</strong><br>'
                '<small>Applies when alerts arrive automatically from a SIEM, EDR, or integration pipeline.</small>'
                '</div>',
                unsafe_allow_html=True,
            )
            api_enable_case_push = st.checkbox(
                "📋 Push **TruePositive / Suspicious** to Case Management",
                value=bool(_cfg("routing.api_source.enable_case_mgmt_push", True)),
                help="When enabled (default), alerts from SIEM pipelines that are TruePositive/Suspicious automatically create cases.",
                key="api_case_push",
            )
            api_enable_soar_close = st.checkbox(
                "⚡ Auto-close **FalsePositive / Benign** in SOAR",
                value=bool(_cfg("routing.api_source.enable_soar_autoclose", True)),
                help="When enabled (default), FalsePositive/Benign verdicts from SIEM pipelines trigger automatic SOAR dismissal.",
                key="api_soar_close",
            )

        st.divider()

        # ── Section 2: Global Controls (Spec §3.2 GlobalRoutingConfig) ──
        st.markdown("### 🌍 Global Controls")

        gcol1, gcol2 = st.columns([1, 2])
        with gcol1:
            global_dry_run = st.toggle(
                "🔒 Master Dry-Run Mode",
                value=bool(_cfg("routing.global.dry_run", False)),
                help=(
                    "**SAFE MODE**: When enabled, all routing decisions are evaluated but NO external API calls "
                    "are made. The response will include 'dry_run_skipped' receipts. "
                    "Disable only when integrations are fully tested."
                ),
                key="global_dry_run",
            )
        with gcol2:
            if global_dry_run:
                st.warning("⚠️ **Dry-Run Mode is ACTIVE** — no external systems will be contacted.", icon="🔒")
            else:
                st.info("Live mode — external dispatchers are active based on policies above.", icon="✅")

        min_trust = st.slider(
            "Minimum RAG Trust Score required for SOAR Auto-Close",
            min_value=1,
            max_value=5,
            value=int(_cfg("routing.global.min_trust_score_for_autoclose", 1)),
            help=(
                "Analyst feedback entries with a trust score below this threshold will not influence "
                "automatic SOAR close decisions. Raise this to require stronger consensus before auto-dismissal."
            ),
            key="min_trust_slider",
        )

        st.divider()

        # ── Section 3: Destination Credentials (Spec §6, item 2) ─
        st.markdown("### 🔐 Destination Credentials")

        dest_col1, dest_col2 = st.columns(2)

        with dest_col1:
            st.markdown("**📋 Case Management**")
            cm_url = st.text_input(
                "Webhook URL",
                value=_cfg("destinations.case_management.url", ""),
                placeholder="https://your-case-management.example.com/api/alerts",
                key="cm_url",
            )
            cm_auth_type = st.selectbox(
                "Authentication Type",
                options=AUTH_TYPES,
                index=AUTH_TYPES.index(_cfg("destinations.case_management.auth_type", "none")),
                key="cm_auth_type",
            )
            cm_api_key = st.text_input(
                "API Key / Bearer Token",
                value=_cfg("destinations.case_management.api_key", ""),
                type="password",
                placeholder="Paste your token here (stored securely in backend)",
                key="cm_api_key",
            )
            cm_timeout = st.number_input(
                "Timeout (seconds)",
                min_value=1.0,
                max_value=60.0,
                value=float(_cfg("destinations.case_management.timeout_seconds", 10.0)),
                step=1.0,
                key="cm_timeout",
            )

        with dest_col2:
            st.markdown("**⚡ SOAR Edge Extension**")
            soar_url = st.text_input(
                "API URL",
                value=_cfg("destinations.soar_edge.url", ""),
                placeholder="https://your-soar.example.com/api/v1/close",
                key="soar_url",
            )
            soar_auth_type = st.selectbox(
                "Authentication Type",
                options=AUTH_TYPES,
                index=AUTH_TYPES.index(_cfg("destinations.soar_edge.auth_type", "none")),
                key="soar_auth_type",
            )
            soar_api_key = st.text_input(
                "API Key / Bearer Token",
                value=_cfg("destinations.soar_edge.api_key", ""),
                type="password",
                placeholder="Paste your token here (stored securely in backend)",
                key="soar_api_key",
            )
            soar_timeout = st.number_input(
                "Timeout (seconds)",
                min_value=1.0,
                max_value=60.0,
                value=float(_cfg("destinations.soar_edge.timeout_seconds", 10.0)),
                step=1.0,
                key="soar_timeout",
            )

        st.divider()

        # ── Save Button (Spec §6, item 3) ────────────────────────
        config_submitted = st.form_submit_button(
            "💾  Save Configuration to Backend",
            type="primary",
            use_container_width=True,
        )

        if config_submitted:
            # Build the SystemSettings payload matching spec §3.2 Pydantic schema
            new_settings = {
                "routing": {
                    "web_source": {
                        "enable_case_mgmt_push": web_enable_case_push,
                        "enable_soar_autoclose": web_enable_soar_close,
                    },
                    "api_source": {
                        "enable_case_mgmt_push": api_enable_case_push,
                        "enable_soar_autoclose": api_enable_soar_close,
                    },
                    # Note: we must use "global" as the key (aliased in Pydantic as global_)
                    "global": {
                        "dry_run": global_dry_run,
                        "min_trust_score_for_autoclose": min_trust,
                    },
                },
                "destinations": {
                    "case_management": {
                        "url": cm_url,
                        "auth_type": cm_auth_type,
                        "api_key": cm_api_key,
                        "timeout_seconds": cm_timeout,
                    },
                    "soar_edge": {
                        "url": soar_url,
                        "auth_type": soar_auth_type,
                        "api_key": soar_api_key,
                        "timeout_seconds": soar_timeout,
                    },
                },
            }

            try:
                put_resp = httpx.put(
                    f"{API_URL}/config",
                    json=new_settings,
                    timeout=CONFIG_TIMEOUT,
                )
                put_resp.raise_for_status()
                resp_data = put_resp.json()
                updated_at = resp_data.get("updated_at", "")[:19].replace("T", " ")
                st.success(
                    f"✅ **Configuration persisted to backend SQLite**\n\n"
                    f"Updated at: `{updated_at} UTC` — Settings survive page reloads and container restarts.",
                    icon="💾",
                )
            except httpx.HTTPStatusError as e:
                st.error(
                    f"Backend rejected the configuration (HTTP {e.response.status_code}): {e.response.text}",
                    icon="🚨",
                )
            except httpx.ConnectError:
                st.error("Cannot reach the API backend. Is it running?", icon="🔴")
            except Exception as e:
                st.error(f"Failed to save configuration: {e}", icon="🚨")

    # ── Backend Connection Info ──────────────────────────────────
    st.divider()
    st.markdown("### 🔌 Backend Connection")
    st.code(f"API_BACKEND_URL = {API_URL}", language="text")
    st.caption(
        "This value is set via the `API_BACKEND_URL` environment variable "
        "(see `docker-compose.yml`). It cannot be changed from the UI."
    )
