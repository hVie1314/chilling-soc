"""
SOC AI Triage System — FastAPI Backend (Orchestrator) v3.0

Responsibilities:
  • POST /analyze           – Embed events → RAG lookup → LLM triage → action routing → return JSON verdict
  • POST /feedback          – Embed log → gradual trust upsert into Qdrant
  • POST /webhook/feedback  – External Case Management webhook → gradual trust ingestion
  • GET  /health            – Liveness probe

Labels (unified):  TruePositive | FalsePositive | Benign | Suspicious
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


class AnalyzeRequest(BaseModel):
    alert_id: str = Field(default="default-alert", description="Alert identifier")
    events: list[str] = Field(..., min_length=1, description="List of raw event log entries")


class TriageResult(BaseModel):
    result: UnifiedLabel
    reason: str


class AnalyzeResponse(BaseModel):
    result: UnifiedLabel
    reason: str
    similar_cases: list[dict] = Field(default_factory=list, description="RAG-retrieved past cases")


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
    """Create the SQLite database and cases table if they don't exist."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
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


# ───────────────────────── Action Routing Scaffolding ─────────────

async def dispatch_to_case_management(alert_id: str, events: list, reason: str) -> None:
    """
    Stub: Dispatch alert to Case Management system for investigation.
    In production, this would POST to a SOAR / Case Management API.
    """
    logger.info(
        "[ACTION] Dispatching to Case Management — alert_id=%s, events=%d, reason=%s",
        alert_id, len(events), reason[:120],
    )


async def trigger_soar_edge_extension_close(alert_id: str, reason: str) -> None:
    """
    Stub: Trigger SOAR edge extension to auto-close the alert.
    In production, this would call a SOAR API to close/dismiss the alert.
    """
    logger.info(
        "[ACTION] Triggering SOAR auto-close — alert_id=%s, reason=%s",
        alert_id, reason[:120],
    )


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
    description="Security Operations Center – AI-powered log triage with RAG feedback loop",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ───────────────────────── Helpers ───────────────────────────────

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
        # Remove first line (```json or ```) and last line (```)
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


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["triage"],
    summary="Triage a multi-event security alert",
)
async def analyze_log(req: AnalyzeRequest):
    """
    1. Save alert to SQLite state bridge.
    2. Iterate through events, embed each unique event.
    3. Query Qdrant per event and aggregate RAG context (deduplicated).
    4. Construct a multi-event prompt and call the LLM.
    5. Parse the structured JSON verdict.
    6. Route action based on verdict.
    7. Return result.
    """
    logger.info(
        "Received /analyze request — alert_id=%s, %d event(s).",
        req.alert_id, len(req.events),
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

    # Step 6 – action routing
    try:
        if triage.result in ("TruePositive", "Suspicious"):
            await dispatch_to_case_management(req.alert_id, req.events, triage.reason)
        elif triage.result in ("FalsePositive", "Benign"):
            await trigger_soar_edge_extension_close(req.alert_id, triage.reason)
    except Exception:
        logger.exception("Action routing failed — verdict still returned to caller.")

    return AnalyzeResponse(
        result=triage.result,
        reason=triage.reason,
        similar_cases=aggregated_cases,
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
