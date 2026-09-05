"""
SOC AI Triage System — FastAPI Backend (Orchestrator) v4.0

Implements io-routing-spec.md v1.0.0 in full:
  • POST /analyze           – Source-aware triage → dynamic action routing → ActionReceipt list
  • POST /feedback          – Gradual trust upsert into Qdrant
  • POST /webhook/feedback  – External Case Management webhook → gradual trust ingestion
  • GET  /config            – Read SystemSettings from SQLite
  • PUT  /config            – Persist SystemSettings to SQLite
  • GET  /health            – Liveness probe

Labels (unified):  TruePositive | FalsePositive | Benign | Suspicious
Input sources:     web_ui | api_siem
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal, Optional

import aiosqlite
import httpx
import numpy as np
# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from openai import AsyncOpenAI
from pydantic import BaseModel, Field
from qdrant_client import QdrantClient
from qdrant_client.http.exceptions import UnexpectedResponse
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)
from sentence_transformers import SentenceTransformer

# ───────────────────────── Configuration ─────────────────────────

QDRANT_HOST: str = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT: int = int(os.getenv("QDRANT_PORT", "6333"))
LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "http://localhost:8000/v1")
LLM_MODEL: str = os.getenv("LLM_MODEL", "fdtn-ai/Foundation-Sec-8B")
COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "soc_knowledge_base")
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "nomic-ai/nomic-embed-text-v1.5")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info").upper()
EMBEDDING_DIM: int = 768  # nomic-embed-text-v1.5 output dimension

SIMILARITY_THRESHOLD: float = 0.92  # Threshold for feedback deduplication
MAX_TRUST_SCORE: int = 5

# SQLite state bridge
DB_PATH: str = os.getenv("SQLITE_DB_PATH", "/app/data/soc_triage.db")

# Unified label set (Case Management verdicts)
VALID_LABELS = {"TruePositive", "FalsePositive", "Benign", "Suspicious"}

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("soc-api")

# ───────────────────────── Pydantic Models ───────────────────────

UnifiedLabel = Literal["TruePositive", "FalsePositive", "Benign", "Suspicious"]
InputSource = Literal["web_ui", "api_siem"]
AuthType = Literal["none", "bearer", "api_key", "basic"]

# ── Routing Configuration Models (spec §3.2) ─────────────────────


class SourceRoutingConfig(BaseModel):
    """Routing policy for a specific input source (web_ui or api_siem)."""
    enable_case_mgmt_push: bool = False
    enable_soar_autoclose: bool = False


class GlobalRoutingConfig(BaseModel):
    """Global overrides applied regardless of source."""
    dry_run: bool = False
    min_trust_score_for_autoclose: int = Field(default=1, ge=1, le=5)


class RoutingConfig(BaseModel):
    """Full routing policy matrix, keyed by input source."""
    web_source: SourceRoutingConfig = Field(
        default_factory=lambda: SourceRoutingConfig(
            enable_case_mgmt_push=False, enable_soar_autoclose=False
        )
    )
    api_source: SourceRoutingConfig = Field(
        default_factory=lambda: SourceRoutingConfig(
            enable_case_mgmt_push=True, enable_soar_autoclose=True
        )
    )
    # Pydantic v2: use model_config to allow "global" as an alias
    global_: GlobalRoutingConfig = Field(
        default_factory=GlobalRoutingConfig,
        alias="global",
    )

    model_config = {"populate_by_name": True}


class DestinationEndpoint(BaseModel):
    """Configuration for a downstream integration endpoint."""
    url: str = Field(default="", description="Endpoint URL (Case Mgmt webhook or SOAR API)")
    auth_type: AuthType = Field(default="none", description="Authentication strategy")
    api_key: str = Field(default="", description="API Key or Bearer Token value")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)


class DestinationsConfig(BaseModel):
    """Registry of all downstream dispatch targets."""
    case_management: DestinationEndpoint = Field(default_factory=DestinationEndpoint)
    soar_edge: DestinationEndpoint = Field(default_factory=DestinationEndpoint)


class SystemSettings(BaseModel):
    """Complete system configuration – persisted as JSON in SQLite system_config table."""
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    destinations: DestinationsConfig = Field(default_factory=DestinationsConfig)


# ── Action Receipt Model ──────────────────────────────────────────


class ActionReceipt(BaseModel):
    """Records the outcome of a single downstream dispatch attempt."""
    destination: str = Field(description="Target system: 'case_management', 'soar_edge', or 'all'")
    status: Literal["success", "skipped", "failed", "dry_run_skipped"] = Field(
        description="Execution result"
    )
    http_status: Optional[int] = Field(default=None, description="HTTP response code from target")
    details: str = Field(default="", description="Short human-readable outcome description")
    error: str = Field(default="", description="Error message if status is 'failed'")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 dispatch timestamp",
    )


# ── Routing Override Model ────────────────────────────────────────


class RoutingOverrides(BaseModel):
    """Per-request overrides to the persisted policy (optional)."""
    force_case_push: bool = False
    force_soar_close: bool = False


# ── Request / Response Models ─────────────────────────────────────


class AnalyzeRequest(BaseModel):
    alert_id: str = Field(default="default-alert", description="Alert identifier")
    events: list[str] = Field(..., min_length=1, description="List of raw event log entries")
    source: InputSource = Field(
        default="web_ui",
        description="Origin of the alert: 'web_ui' (analyst) or 'api_siem' (automated pipeline)",
    )
    routing_overrides: RoutingOverrides = Field(
        default_factory=RoutingOverrides,
        description="Optional per-request overrides to the system routing policy",
    )


class TriageResult(BaseModel):
    result: UnifiedLabel
    reason: str


class AnalyzeResponse(BaseModel):
    alert_id: str
    result: UnifiedLabel
    reason: str
    similar_cases: list[dict] = Field(default_factory=list, description="RAG-retrieved past cases")
    actions_dispatched: list[ActionReceipt] = Field(
        default_factory=list,
        description="List of downstream dispatch receipts executed for this alert",
    )


class FeedbackRequest(BaseModel):
    raw_log: str = Field(..., min_length=1, description="Raw log entry to store feedback for")
    label: UnifiedLabel
    analyst_comment: str = Field(default="", description="Analyst comment for the feedback")


class FeedbackResponse(BaseModel):
    status: str
    point_id: str
    action: str = Field(default="inserted", description="'inserted', 'reinforced', or 'corrected'")
    trust_score: int = Field(default=1)


class WebhookFeedbackRequest(BaseModel):
    event: str = Field(default="", description="Event log text (optional context)")
    feedback_id: str = Field(default="", description="External feedback identifier")
    case_id: str = Field(..., description="Matches alert_id in the cases table")
    user_id: str = Field(default="", description="External user identifier")
    verdict: UnifiedLabel
    comment: str = Field(default="", description="Analyst comment")
    created_at: str = Field(default="", description="ISO 8601 timestamp from external system")


class WebhookResponse(BaseModel):
    status: str


# ───────────────────────── Global Resources ──────────────────────

embedder: SentenceTransformer | None = None
qdrant: QdrantClient | None = None
llm_client: AsyncOpenAI | None = None


def _ensure_collection(client: QdrantClient) -> None:
    """Create the Qdrant collection if it doesn't already exist."""
    try:
        client.get_collection(COLLECTION_NAME)
        logger.info("Qdrant collection '%s' already exists.", COLLECTION_NAME)
    except (UnexpectedResponse, Exception):
        logger.info("Creating Qdrant collection '%s' ...", COLLECTION_NAME)
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
        )
        logger.info("Collection '%s' created.", COLLECTION_NAME)


# ───────────────────────── SQLite State Bridge ───────────────────

async def _init_db() -> None:
    """Create the SQLite database and all required tables if they don't exist."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        # ── Alert cases table ──
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id    TEXT    NOT NULL,
                events_json TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_cases_alert_id ON cases (alert_id)
        """)

        # ── System configuration table (singleton row, id always = 1) ──
        # Spec §5.1: one row stores the entire SystemSettings as JSON.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                config_json TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL
            )
        """)

        await db.commit()
    logger.info("SQLite database initialised at '%s'.", DB_PATH)


async def _save_case(alert_id: str, events: list[str]) -> None:
    """Persist an incoming alert to the SQLite cases table."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO cases (alert_id, events_json, created_at) VALUES (?, ?, ?)",
            (alert_id, json.dumps(events, ensure_ascii=False), datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()
    logger.info("Saved case to SQLite — alert_id=%s", alert_id)


async def _get_events_by_alert_id(alert_id: str) -> list[str] | None:
    """Retrieve the original events for a given alert_id from SQLite."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT events_json FROM cases WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
            (alert_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row["events_json"])
    return None


# ───────────────────────── Configuration Persistence ─────────────

async def _load_config() -> SystemSettings:
    """
    Read SystemSettings from the system_config table.
    Returns hardcoded defaults (matching spec §3.2) on first run or missing row.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT config_json FROM system_config WHERE id = 1"
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    raw = json.loads(row[0])
                    return SystemSettings.model_validate(raw)
    except Exception:
        logger.exception("Failed to load config from SQLite — using defaults.")
    return SystemSettings()


async def _save_config(settings: SystemSettings) -> None:
    """Persist SystemSettings JSON to the system_config singleton row (id = 1)."""
    config_json = settings.model_dump_json(by_alias=True)
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO system_config (id, config_json, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE
                SET config_json = excluded.config_json,
                    updated_at  = excluded.updated_at
            """,
            (config_json, now),
        )
        await db.commit()
    logger.info("System configuration persisted to SQLite.")


# ───────────────────────── Lifespan ──────────────────────────────

@asynccontextmanager
async def lifespan(application: FastAPI):  # noqa: ARG001
    """Startup / shutdown lifecycle hook."""
    global embedder, qdrant, llm_client  # noqa: PLW0603

    # ── Sentence-Transformer embedder ──
    logger.info("Loading embedding model '%s' ...", EMBEDDING_MODEL)
    embedder = SentenceTransformer(EMBEDDING_MODEL, trust_remote_code=True)
    logger.info("Embedding model loaded.")

    # ── Qdrant client ──
    logger.info("Connecting to Qdrant at %s:%d ...", QDRANT_HOST, QDRANT_PORT)
    qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=30)
    _ensure_collection(qdrant)

    # ── OpenAI-compatible async client (works with vLLM, Ollama, etc.) ──
    llm_client = AsyncOpenAI(base_url=LLM_BASE_URL, api_key="not-needed")
    logger.info("LLM client initialised (base_url=%s, model=%s).", LLM_BASE_URL, LLM_MODEL)

    # ── SQLite state bridge ──
    await _init_db()

    yield  # application runs

    # ── Cleanup ──
    if qdrant:
        qdrant.close()
    logger.info("Shutdown complete.")

# ───────────────────────── FastAPI App ───────────────────────────

app = FastAPI(
    title="SOC AI Triage API",
    description="Security Operations Center – AI-powered log triage with RAG feedback loop and dynamic I/O routing",
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ───────────────────────── Embedding & RAG Helpers ───────────────

def _embed(text: str) -> list[float]:
    """Produce a dense vector from text using the sentence-transformer model."""
    vec = embedder.encode(text, normalize_embeddings=True)  # type: ignore[union-attr]
    return vec.tolist() if isinstance(vec, np.ndarray) else list(vec)


def _search_similar(vector: list[float], top_k: int = 2) -> list[dict]:
    """
    Search Qdrant for the most similar past cases.
    Returns an empty list when the collection is empty (first-run graceful).
    Includes trust_score and comment in returned payloads.
    """
    try:
        collection_info = qdrant.get_collection(COLLECTION_NAME)  # type: ignore[union-attr]
        if collection_info.points_count == 0:
            logger.info("Knowledge base is empty — skipping RAG retrieval.")
            return []

        hits = qdrant.search(  # type: ignore[union-attr]
            collection_name=COLLECTION_NAME,
            query_vector=vector,
            limit=top_k,
            with_payload=True,
        )
        results = []
        for hit in hits:
            payload = hit.payload or {}
            results.append(
                {
                    "score": round(hit.score, 4),
                    "raw_log": payload.get("raw_log", ""),
                    "label": payload.get("label", ""),
                    "comment": payload.get("comment", payload.get("analyst_comment", "")),
                    "trust_score": payload.get("trust_score", 1),
                }
            )
        return results
    except Exception:
        logger.exception("RAG search failed — continuing without history.")
        return []


def _build_prompt(events: list[str], similar_cases: list[dict]) -> list[dict]:
    """
    Build the Chat Completions messages list for multi-event alerts.
    Includes trust-aware RAG context and strict Vietnamese output instructions.
    Uses unified labels: TruePositive, FalsePositive, Benign, Suspicious.
    """
    system_content = (
        "You are a senior SOC analyst AI. Your task is to triage a security alert containing one or more event logs.\n"
        "STRICT RULES:\n"
        '1. Output ONLY a valid JSON object: {"result": "<label>", "reason": "<Vietnamese explanation>"}\n'
        "2. The <label> MUST be exactly one of: TruePositive, FalsePositive, Benign, Suspicious.\n"
        "3. If ANY event in the alert is malicious, the whole result MUST be TruePositive or Suspicious.\n"
        "4. The 'reason' MUST be written in Vietnamese and be concise (maximum 1-2 sentences). "
        "If a malicious event exists, only explain the most malicious event.\n"
        "5. Do NOT include any text outside the JSON object.\n"
    )

    user_parts: list[str] = []

    # RAG context with trust scoring
    if similar_cases:
        user_parts.append("### Analyst Knowledge Base (past verdicts):")
        for case in similar_cases:
            trust = case.get("trust_score", 1)
            label = case.get("label", "?")
            comment = case.get("comment", "")
            user_parts.append(
                f"- Analyst labelled as [{label}] "
                f"with Trust Score [{trust}/{MAX_TRUST_SCORE}]. "
                f"Comment: [{comment}]"
            )
        user_parts.append("")  # blank line separator

    # Enumerated event list
    user_parts.append("### Alert Events to Triage:")
    for idx, event in enumerate(events, 1):
        user_parts.append(f"  {idx}. {event}")

    return [
        {"role": "system", "content": system_content},
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def _parse_llm_response(content: str) -> TriageResult:
    """
    Parse the LLM response into a TriageResult.
    Handles both clean JSON and responses wrapped in markdown code fences.
    """
    text = content.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned non-JSON: %s", text[:500])
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM returned unparseable response: {text[:300]}",
        ) from exc

    result_val = data.get("result", "").strip()
    reason_val = data.get("reason", "No reason provided.").strip()

    if result_val not in VALID_LABELS:
        logger.warning("LLM returned unexpected result value: '%s'. Defaulting to Suspicious.", result_val)
        result_val = "Suspicious"

    return TriageResult(result=result_val, reason=reason_val)


# ───────────────────────── Gradual Trust Logic ───────────────────

async def _apply_gradual_trust(
    raw_log: str,
    label: str,
    comment: str,
) -> FeedbackResponse:
    """
    Core gradual trust logic — shared by /feedback and /webhook/feedback.
    Embed the raw log, query Qdrant for near-duplicates, and insert/reinforce/correct.
    """
    vector = _embed(raw_log)

    # ── Query Qdrant for top-1 match to check for near-duplicate ──
    existing_match = None
    try:
        collection_info = qdrant.get_collection(COLLECTION_NAME)  # type: ignore[union-attr]
        if collection_info.points_count > 0:
            hits = qdrant.search(  # type: ignore[union-attr]
                collection_name=COLLECTION_NAME,
                query_vector=vector,
                limit=1,
                with_payload=True,
            )
            if hits and hits[0].score > SIMILARITY_THRESHOLD:
                existing_match = hits[0]
                logger.info(
                    "Found existing match (score=%.4f, id=%s, label=%s).",
                    existing_match.score, existing_match.id,
                    (existing_match.payload or {}).get("label", "?"),
                )
    except Exception:
        logger.exception("Qdrant search during feedback failed — will insert as new.")

    # ── Determine action: insert / reinforce / correct ──
    if existing_match is None:
        # No close match → INSERT new point
        point_id = str(uuid.uuid4())
        trust_score = 1
        action = "inserted"
        payload = {
            "raw_log": raw_log,
            "label": label,
            "comment": comment,
            "trust_score": trust_score,
        }
        logger.info("No close match — inserting new point (id=%s).", point_id)
    else:
        # Reuse the existing point's ID to avoid duplicates
        point_id = str(existing_match.id)
        existing_payload = existing_match.payload or {}
        existing_label = existing_payload.get("label", "")
        existing_trust = existing_payload.get("trust_score", 1)

        if existing_label == label:
            # Same label → REINFORCE: increment trust, update comment
            trust_score = min(existing_trust + 1, MAX_TRUST_SCORE)
            action = "reinforced"
            logger.info(
                "Same label — reinforcing (trust_score %d → %d).",
                existing_trust, trust_score,
            )
        else:
            # Different label → CORRECT: overwrite label, reset trust
            trust_score = 1
            action = "corrected"
            logger.info(
                "Label conflict (%s → %s) — correcting, trust reset to 1.",
                existing_label, label,
            )

        payload = {
            "raw_log": raw_log,
            "label": label,
            "comment": comment,
            "trust_score": trust_score,
        }

    # ── Upsert into Qdrant ──
    try:
        qdrant.upsert(  # type: ignore[union-attr]
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload,
                )
            ],
        )
    except Exception as exc:
        logger.exception("Qdrant upsert failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Vector DB write failed: {exc}",
        ) from exc

    logger.info("Feedback stored — point_id=%s, action=%s, trust_score=%d", point_id, action, trust_score)
    return FeedbackResponse(
        status="stored",
        point_id=point_id,
        action=action,
        trust_score=trust_score,
    )


# ───────────────────────── Action Routing Engine ─────────────────
# Implements io-routing-spec.md §5.2 and §5.3

async def dispatch_to_case_management(
    endpoint: DestinationEndpoint,
    alert_id: str,
    events: list[str],
    verdict: str,
    reason: str,
) -> ActionReceipt:
    """
    Spec §5.3: Real HTTP dispatcher for Case Management systems.
    Supports bearer token, X-API-Key, and unauthenticated calls.
    """
    if not endpoint.url:
        logger.info("[ROUTING] Case Management URL not configured — skipping dispatch.")
        return ActionReceipt(
            destination="case_management",
            status="skipped",
            details="No webhook URL configured. Set it via PUT /config.",
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}

    if endpoint.auth_type == "bearer" and endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    elif endpoint.auth_type == "api_key" and endpoint.api_key:
        headers["X-API-Key"] = endpoint.api_key
    elif endpoint.auth_type == "basic" and endpoint.api_key:
        # api_key field carries "username:password" for basic auth
        import base64
        encoded = base64.b64encode(endpoint.api_key.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    payload = {
        "alert_id": alert_id,
        "events": events,
        "verdict": verdict,
        "triage_summary": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "[ROUTING] Dispatching to Case Management — alert_id=%s, verdict=%s, url=%s",
        alert_id, verdict, endpoint.url,
    )

    try:
        async with httpx.AsyncClient(timeout=endpoint.timeout_seconds) as client:
            resp = await client.post(endpoint.url, json=payload, headers=headers)
            resp.raise_for_status()
            logger.info(
                "[ROUTING] Case Management dispatch succeeded — HTTP %d for alert_id=%s",
                resp.status_code, alert_id,
            )
            return ActionReceipt(
                destination="case_management",
                status="success",
                http_status=resp.status_code,
                details=resp.text[:200],
            )
    except httpx.HTTPStatusError as exc:
        logger.error(
            "[ROUTING] Case Management returned HTTP %d: %s",
            exc.response.status_code, exc.response.text[:200],
        )
        return ActionReceipt(
            destination="case_management",
            status="failed",
            http_status=exc.response.status_code,
            error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        )
    except Exception as exc:
        logger.error("[ROUTING] Case Management dispatch failed: %s", exc)
        return ActionReceipt(
            destination="case_management",
            status="failed",
            error=str(exc),
        )


async def trigger_soar_edge_extension_close(
    endpoint: DestinationEndpoint,
    alert_id: str,
    verdict: str,
    reason: str,
) -> ActionReceipt:
    """
    Spec §5.3: Real HTTP dispatcher for SOAR Edge auto-close.
    Supports bearer token, X-API-Key, and unauthenticated calls.
    """
    if not endpoint.url:
        logger.info("[ROUTING] SOAR Edge URL not configured — skipping auto-close.")
        return ActionReceipt(
            destination="soar_edge",
            status="skipped",
            details="No SOAR API URL configured. Set it via PUT /config.",
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}

    if endpoint.auth_type == "bearer" and endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    elif endpoint.auth_type == "api_key" and endpoint.api_key:
        headers["X-API-Key"] = endpoint.api_key
    elif endpoint.auth_type == "basic" and endpoint.api_key:
        import base64
        encoded = base64.b64encode(endpoint.api_key.encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    payload = {
        "alert_id": alert_id,
        "action": "auto_close",
        "verdict": verdict,
        "reason": reason,
        "closed_at": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(
        "[ROUTING] Triggering SOAR auto-close — alert_id=%s, verdict=%s, url=%s",
        alert_id, verdict, endpoint.url,
    )

    try:
        async with httpx.AsyncClient(timeout=endpoint.timeout_seconds) as client:
            resp = await client.post(endpoint.url, json=payload, headers=headers)
            resp.raise_for_status()
            logger.info(
                "[ROUTING] SOAR auto-close succeeded — HTTP %d for alert_id=%s",
                resp.status_code, alert_id,
            )
            return ActionReceipt(
                destination="soar_edge",
                status="success",
                http_status=resp.status_code,
                details=resp.text[:200],
            )
    except httpx.HTTPStatusError as exc:
        logger.error(
            "[ROUTING] SOAR returned HTTP %d: %s",
            exc.response.status_code, exc.response.text[:200],
        )
        return ActionReceipt(
            destination="soar_edge",
            status="failed",
            http_status=exc.response.status_code,
            error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        )
    except Exception as exc:
        logger.error("[ROUTING] SOAR auto-close dispatch failed: %s", exc)
        return ActionReceipt(
            destination="soar_edge",
            status="failed",
            error=str(exc),
        )


async def route_actions(
    alert_id: str,
    events: list[str],
    triage: TriageResult,
    source: InputSource,
    overrides: RoutingOverrides,
    config: SystemSettings,
) -> list[ActionReceipt]:
    """
    Spec §5.2: Dynamic action routing engine.
    Evaluates dry_run, source-based policies, and per-request overrides.
    Returns a list of ActionReceipt objects to embed in AnalyzeResponse.
    """
    receipts: list[ActionReceipt] = []

    # ── 1. Global Dry Run Guard ───────────────────────────────────
    if config.routing.global_.dry_run:
        logger.info("[ROUTING] Dry-run mode active — all side-effects suppressed.")
        return [
            ActionReceipt(
                destination="all",
                status="dry_run_skipped",
                details="Global dry-run mode is enabled. No external systems were contacted.",
            )
        ]

    # ── 2. Resolve policy from input source ───────────────────────
    policy: SourceRoutingConfig = (
        config.routing.web_source if source == "web_ui" else config.routing.api_source
    )

    logger.info(
        "[ROUTING] Evaluating policy for source=%s, verdict=%s | "
        "case_push=%s, soar_close=%s | overrides: force_case=%s, force_soar=%s",
        source, triage.result,
        policy.enable_case_mgmt_push, policy.enable_soar_autoclose,
        overrides.force_case_push, overrides.force_soar_close,
    )

    # ── 3. Route TruePositive / Suspicious → Case Management ──────
    if triage.result in ("TruePositive", "Suspicious"):
        should_push = policy.enable_case_mgmt_push or overrides.force_case_push
        if should_push:
            receipt = await dispatch_to_case_management(
                endpoint=config.destinations.case_management,
                alert_id=alert_id,
                events=events,
                verdict=triage.result,
                reason=triage.reason,
            )
            receipts.append(receipt)
        else:
            logger.info(
                "[ROUTING] Case Management push disabled for source=%s — no dispatch.", source
            )

    # ── 4. Route FalsePositive / Benign → SOAR Auto-Close ─────────
    elif triage.result in ("FalsePositive", "Benign"):
        should_close = policy.enable_soar_autoclose or overrides.force_soar_close
        if should_close:
            receipt = await trigger_soar_edge_extension_close(
                endpoint=config.destinations.soar_edge,
                alert_id=alert_id,
                verdict=triage.result,
                reason=triage.reason,
            )
            receipts.append(receipt)
        else:
            logger.info(
                "[ROUTING] SOAR auto-close disabled for source=%s — no dispatch.", source
            )

    return receipts


# ───────────────────────── Endpoints ─────────────────────────────

@app.get("/health", tags=["ops"])
async def health_check():
    """Liveness / readiness probe with optional dependency checks."""
    health = {"status": "healthy"}

    # Qdrant check
    try:
        qdrant.get_collection(COLLECTION_NAME)  # type: ignore[union-attr]
        health["qdrant"] = "connected"
    except Exception:
        health["qdrant"] = "unreachable"

    # LLM check (non-blocking, informational — 3s timeout)
    try:
        models = await asyncio.wait_for(llm_client.models.list(), timeout=3.0)  # type: ignore[union-attr]
        health["llm"] = "connected"
        health["llm_models"] = [m.id for m in models.data]  # type: ignore[union-attr]
    except Exception:
        health["llm"] = "unreachable"

    # SQLite check
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT COUNT(*) FROM cases") as cursor:
                row = await cursor.fetchone()
                health["sqlite"] = "connected"
                health["sqlite_cases_count"] = row[0] if row else 0
    except Exception:
        health["sqlite"] = "unreachable"

    return health


@app.get(
    "/config",
    response_model=SystemSettings,
    tags=["config"],
    summary="Get current system routing & destination configuration",
)
async def get_config():
    """
    Read the persisted SystemSettings from SQLite.
    Returns factory defaults if no configuration has been saved yet.
    API keys are returned as stored (frontend should mask them).
    """
    settings = await _load_config()
    logger.info("GET /config — returning current system settings.")
    return settings


@app.put(
    "/config",
    tags=["config"],
    summary="Update system routing & destination configuration",
)
async def update_config(settings: SystemSettings):
    """
    Persist SystemSettings JSON to the system_config singleton table.
    This is the canonical write path from the Streamlit Settings UI.
    """
    await _save_config(settings)
    logger.info("PUT /config — system settings saved successfully.")
    return {"status": "saved", "updated_at": datetime.now(timezone.utc).isoformat()}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["triage"],
    summary="Triage a multi-event security alert with dynamic I/O routing",
)
async def analyze_log(req: AnalyzeRequest):
    """
    Full triage pipeline per io-routing-spec.md §4.1 and §5:

    1. Save alert to SQLite state bridge.
    2. Embed each unique event and aggregate RAG context (deduplicated).
    3. Construct a multi-event prompt and call the LLM.
    4. Parse the structured JSON verdict.
    5. Load SystemSettings from SQLite.
    6. Execute route_actions() based on source, verdict, and policies.
    7. Return verdict + actions_dispatched receipts.
    """
    logger.info(
        "Received /analyze request — alert_id=%s, source=%s, %d event(s).",
        req.alert_id, req.source, len(req.events),
    )

    # Step 0 – persist to SQLite BEFORE analysis
    try:
        await _save_case(req.alert_id, req.events)
    except Exception:
        logger.exception("Failed to save case to SQLite — continuing with analysis.")

    # Step 1 & 2 – embed each unique event and aggregate RAG results
    seen_events: set[str] = set()
    aggregated_cases: list[dict] = []
    seen_rag_logs: set[str] = set()  # deduplicate RAG hits across events

    for event in req.events:
        event_stripped = event.strip()
        if not event_stripped or event_stripped in seen_events:
            continue
        seen_events.add(event_stripped)

        vector = _embed(event_stripped)
        cases = _search_similar(vector, top_k=2)

        for case in cases:
            rag_log = case.get("raw_log", "")
            if rag_log not in seen_rag_logs:
                seen_rag_logs.add(rag_log)
                aggregated_cases.append(case)

    logger.info("RAG returned %d unique similar case(s) across all events.", len(aggregated_cases))

    # Step 3 – build multi-event prompt
    messages = _build_prompt(
        [e.strip() for e in req.events if e.strip()],
        aggregated_cases,
    )

    # Step 4 – call LLM
    # Try with guided_json (vLLM structured output) first;
    # fall back to plain JSON-mode request for providers that don't support it (e.g. Ollama).
    guided_json_schema = json.dumps(
        {
            "type": "object",
            "properties": {
                "result": {
                    "type": "string",
                    "enum": ["TruePositive", "FalsePositive", "Benign", "Suspicious"],
                },
                "reason": {"type": "string"},
            },
            "required": ["result", "reason"],
        }
    )

    chat_response = None
    try:
        # Attempt with vLLM guided decoding
        chat_response = await llm_client.chat.completions.create(  # type: ignore[union-attr]
            model=LLM_MODEL,
            messages=messages,
            temperature=0.1,
            max_tokens=256,
            extra_body={"guided_json": guided_json_schema},
        )
    except Exception as guided_exc:
        logger.warning(
            "LLM call with guided_json failed (%s); retrying without it.",
            type(guided_exc).__name__,
        )
        try:
            chat_response = await llm_client.chat.completions.create(  # type: ignore[union-attr]
                model=LLM_MODEL,
                messages=messages,
                temperature=0.1,
                max_tokens=256,
            )
        except Exception as plain_exc:
            logger.exception("LLM call failed.")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"LLM engine unreachable or returned error: {plain_exc}",
            ) from plain_exc

    raw_content = chat_response.choices[0].message.content or ""
    logger.debug("LLM raw response: %s", raw_content[:500])

    # Step 5 – parse
    triage = _parse_llm_response(raw_content)

    # Step 6 – load config and execute dynamic routing
    config = await _load_config()
    actions_dispatched: list[ActionReceipt] = []
    try:
        actions_dispatched = await route_actions(
            alert_id=req.alert_id,
            events=req.events,
            triage=triage,
            source=req.source,
            overrides=req.routing_overrides,
            config=config,
        )
    except Exception:
        logger.exception("route_actions raised an unexpected error — verdict still returned.")

    return AnalyzeResponse(
        alert_id=req.alert_id,
        result=triage.result,
        reason=triage.reason,
        similar_cases=aggregated_cases,
        actions_dispatched=actions_dispatched,
    )


@app.post(
    "/feedback",
    response_model=FeedbackResponse,
    tags=["feedback"],
    summary="Submit analyst feedback with gradual trust scoring",
)
async def submit_feedback(req: FeedbackRequest):
    """
    Embed the raw log and apply gradual trust scoring:
      - No close match (score <= 0.92): INSERT new point with trust_score=1.
      - Close match, same label: REINFORCE — increment trust_score (max 5), update comment.
      - Close match, different label: CORRECT — overwrite label & comment, reset trust_score=1.
    """
    logger.info("Received /feedback — label=%s, comment=%s", req.label, req.analyst_comment[:80])
    return await _apply_gradual_trust(req.raw_log, req.label, req.analyst_comment)


@app.post(
    "/webhook/feedback",
    response_model=WebhookResponse,
    tags=["webhook"],
    summary="Receive external Case Management feedback via webhook",
    status_code=status.HTTP_200_OK,
)
async def webhook_feedback(req: WebhookFeedbackRequest):
    """
    Ingest feedback from an external Case Management / SOAR system.

    1. Look up the original events from SQLite using case_id (== alert_id).
    2. If not found, log a warning and return 200 OK.
    3. If found, run the gradual trust logic on each original event.
    4. Always return HTTP 200 {"status": "received"}.
    """
    logger.info(
        "Received /webhook/feedback — case_id=%s, verdict=%s, user_id=%s",
        req.case_id, req.verdict, req.user_id,
    )

    # Step 1 – retrieve original events from SQLite
    events = await _get_events_by_alert_id(req.case_id)

    if events is None:
        logger.warning(
            "Webhook: No case found for case_id=%s in SQLite. "
            "Acknowledging without processing.",
            req.case_id,
        )
        return WebhookResponse(status="received")

    # Step 2 – apply gradual trust for each original event
    for event in events:
        event_stripped = event.strip()
        if not event_stripped:
            continue
        try:
            await _apply_gradual_trust(event_stripped, req.verdict, req.comment)
        except HTTPException:
            # Qdrant write failures — log but don't fail the webhook
            logger.exception(
                "Gradual trust upsert failed for event in case_id=%s, skipping.",
                req.case_id,
            )
        except Exception:
            logger.exception(
                "Unexpected error during gradual trust for case_id=%s, skipping.",
                req.case_id,
            )

    logger.info("Webhook processed — case_id=%s, %d event(s) updated.", req.case_id, len(events))
    return WebhookResponse(status="received")
