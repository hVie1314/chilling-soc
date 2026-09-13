"""
SOC AI Triage System — FastAPI Backend (Orchestrator)

Responsibilities:
  • POST /analyze  – Embed events → RAG lookup → LLM triage → return JSON verdict
  • POST /feedback – Embed log → gradual trust upsert into Qdrant
  • GET  /health   – Liveness probe
"""

from __future__ import annotations

import re

import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Literal

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

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("soc-api")

# ───────────────────────── Pydantic Models ───────────────────────

class AnalyzeRequest(BaseModel):
    alert_id: str = Field(default="web-dummy", description="Alert identifier")
    events: list[str] = Field(..., min_length=1, description="List of raw event log entries")


class TriageResult(BaseModel):
    result: Literal["FP", "TP", "Incident"]
    reason: str


class AnalyzeResponse(BaseModel):
    result: Literal["FP", "TP", "Incident"]
    reason: str
    similar_cases: list[dict] = Field(default_factory=list, description="RAG-retrieved past cases")


class FeedbackRequest(BaseModel):
    raw_log: str = Field(..., min_length=1, description="Raw log entry to store feedback for")
    label: Literal["FP", "TP", "Incident"]
    analyst_comment: str = Field(default="", description="Analyst comment for the feedback")


class FeedbackResponse(BaseModel):
    status: str
    point_id: str
    action: str = Field(default="inserted", description="'inserted', 'reinforced', or 'corrected'")
    trust_score: int = Field(default=1)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Analyst query")
    session_id: str = Field(default="", description="Case ID or session identifier")
    case_context: str = Field(default="", description="Optional context about the incident")


class ChatResponse(BaseModel):
    response: str
    model: str
    session_id: str

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

    yield  # application runs

    # ── Cleanup ──
    if qdrant:
        qdrant.close()
    logger.info("Shutdown complete.")

# ───────────────────────── FastAPI App ───────────────────────────

app = FastAPI(
    title="SOC AI Triage API",
    description="Security Operations Center – AI-powered log triage with RAG feedback loop",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
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
    """
    system_content = (
        "You are a senior SOC analyst AI. Your task is to triage a security alert containing one or more event logs.\n"
        "STRICT RULES:\n"
        "1. Output ONLY a valid JSON object: {\"result\": \"FP\" | \"TP\" | \"Incident\", \"reason\": \"<Vietnamese explanation>\"}\n"
        "2. If ANY event in the alert is malicious, the whole result MUST be TP or Incident.\n"
        "3. The 'reason' MUST be written in Vietnamese.\n"
        "4. The 'reason' MUST be concise (maximum 1-2 sentences). "
        "If a TP or malicious event exists, do NOT explain FP logs; only explain the malicious event.\n"
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
                f"- Log pattern matched. Analyst labelled as [{label}] "
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
    Handles (in order):
      1. Clean JSON
      2. Markdown code fences (```json ... ```)
      3. Regex extraction of the first {...} JSON object in free-text
      4. Safe fallback — classify as TP with original text as reason
    """
    text = content.strip()

    # ── 1. Strip markdown code fences if present ──
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    # ── 2. Try direct JSON parse ──
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # ── 3. Regex: extract first {...} block from free-text ──
        match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                logger.warning("LLM response was not pure JSON; extracted JSON block via regex.")
            except json.JSONDecodeError:
                data = None
        else:
            data = None

        if data is None:
            # ── 4. Safe fallback: cannot parse → TP with truncated text as reason ──
            logger.error(
                "LLM returned unparseable response (len=%d): %s",
                len(text), text[:300],
            )
            reason_fallback = text[:300] if text else "LLM did not return a structured response."
            return TriageResult(result="TP", reason=reason_fallback)

    result_val = data.get("result", "").strip()
    reason_val = data.get("reason", "No reason provided.").strip()

    if result_val not in {"FP", "TP", "Incident"}:
        logger.warning("LLM returned unexpected result value: '%s'. Defaulting to TP.", result_val)
        result_val = "TP"

    return TriageResult(result=result_val, reason=reason_val)

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

    return health


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["triage"],
    summary="Triage a multi-event security alert",
)
async def analyze_log(req: AnalyzeRequest):
    """
    1. Iterate through events, embed each unique event.
    2. Query Qdrant per event and aggregate RAG context (deduplicated).
    3. Construct a multi-event prompt and call the LLM.
    4. Parse the structured JSON verdict and return it.
    """
    logger.info(
        "Received /analyze request — alert_id=%s, %d event(s).",
        req.alert_id, len(req.events),
    )

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
                    "enum": ["FP", "TP", "Incident"],
                },
                "reason": {"type": "string"},
            },
            "required": ["result", "reason"],
        }
    )

    chat_response = None
    try:
        # Attempt with response_format and guided_json
        chat_response = await llm_client.chat.completions.create(  # type: ignore[union-attr]
            model=LLM_MODEL,
            messages=messages,
            temperature=0.1,
            max_tokens=256,
            response_format={"type": "json_object"},
            extra_body={"guided_json": guided_json_schema},
        )
    except Exception as guided_exc:
        logger.warning(
            "LLM call with guided_json failed (%s); retrying with standard json_object.",
            type(guided_exc).__name__,
        )
        try:
            chat_response = await llm_client.chat.completions.create(  # type: ignore[union-attr]
                model=LLM_MODEL,
                messages=messages,
                temperature=0.1,
                max_tokens=256,
                response_format={"type": "json_object"},
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

    vector = _embed(req.raw_log)

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
            "raw_log": req.raw_log,
            "label": req.label,
            "comment": req.analyst_comment,
            "trust_score": trust_score,
        }
        logger.info("No close match — inserting new point (id=%s).", point_id)
    else:
        # Reuse the existing point's ID to avoid duplicates
        point_id = str(existing_match.id)
        existing_payload = existing_match.payload or {}
        existing_label = existing_payload.get("label", "")
        existing_trust = existing_payload.get("trust_score", 1)

        if existing_label == req.label:
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
                existing_label, req.label,
            )

        payload = {
            "raw_log": req.raw_log,
            "label": req.label,
            "comment": req.analyst_comment,
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


@app.post(
    "/chat",
    response_model=ChatResponse,
    tags=["chat"],
    summary="Interactive SOC Incident Copilot Chat with RAG Context",
)
async def chat_incident(req: ChatRequest):
    """
    Interactive SOC Copilot:
    Answers analyst queries about the incident, logs, attack behavior, and containment steps.
    """
    logger.info("Received /chat request — session_id=%s, len=%d", req.session_id, len(req.message))

    # Optional RAG lookup based on query and context
    search_query = f"{req.case_context} {req.message}".strip()
    vector = _embed(search_query)
    similar_cases = _search_similar(vector, top_k=2)

    system_prompt = (
        "Bạn là CyberAI Copilot — Trợ lý Chuyên gia Phân tích Sự cố SOC thuộc Trung tâm Giám sát Điều hành An ninh Mạng NCS (NCS Fusion Center).\n"
        "Nhiệm vụ của bạn là hỗ trợ Phân tích viên SOC (Analyst) điều tra, mổ xẻ hành vi mã độc/lệnh shell, giải thích mức độ nguy hại, "
        "và đề xuất các phương án xử lý, ngăn chặn, cô lập khẩn cấp.\n"
        "QUY TẮC PHẢN HỒI:\n"
        "1. Trả lời bằng Tiếng Việt kỹ thuật chuyên nghiệp, súc tích, đi thẳng vào bản chất kỹ thuật (MITRE ATT&CK, tiến trình, log forensics).\n"
        "2. Không dài dòng triết lý. Nêu rõ các bước hành động cụ thể khi được hỏi về cô lập/xử lý.\n"
        "3. Nếu có mã độc hoặc lệnh cmd/powershell bất thường (như w3wp.exe sinh cmd whoami), giải thích rõ cơ chế webshell/RCE."
    )

    messages = [{"role": "system", "content": system_prompt}]

    if similar_cases:
        rag_context = "### Cơ sở tri thức tương đồng từ quá khứ (RAG):\n"
        for c in similar_cases:
            rag_context += f"- Log: {c.get('raw_log', '')[:200]} | Nhãn: [{c.get('label', '')}] | Ghi chú: {c.get('comment', '')}\n"
        messages.append({"role": "system", "content": rag_context})

    if req.case_context:
        messages.append({"role": "system", "content": f"### Bối cảnh Sự cố Hiện tại:\n{req.case_context}"})

    messages.append({"role": "user", "content": req.message})

    try:
        chat_completion = await llm_client.chat.completions.create(  # type: ignore[union-attr]
            model=LLM_MODEL,
            messages=messages,
            temperature=0.2,
            max_tokens=512,
        )
        content = chat_completion.choices[0].message.content or "Không thể khởi tạo nội dung phản hồi từ AI."
    except Exception as exc:
        logger.exception("LLM chat completion failed.")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Lỗi kết nối tới mô hình AI LLM: {exc}",
        ) from exc

    return ChatResponse(
        response=content.strip(),
        model=LLM_MODEL,
        session_id=req.session_id,
    )
