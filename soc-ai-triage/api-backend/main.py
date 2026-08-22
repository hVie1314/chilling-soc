"""
SOC AI Triage System — FastAPI Backend (Orchestrator)

Responsibilities:
  • POST /analyze  – Embed log → RAG lookup → LLM triage → return JSON verdict
  • POST /feedback – Embed log → store analyst feedback into Qdrant
  • GET  /health   – Liveness probe
"""

from __future__ import annotations

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
COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "soc_knowledge_base")
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "nomic-ai/nomic-embed-text-v1.5")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info").upper()
EMBEDDING_DIM: int = 768  # nomic-embed-text-v1.5 output dimension

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("soc-api")

# ───────────────────────── Pydantic Models ───────────────────────

class AnalyzeRequest(BaseModel):
    raw_log: str = Field(..., min_length=1, description="Raw security log entry")


class TriageResult(BaseModel):
    result: Literal["FP", "TP", "Incident"]
    reason: str


class AnalyzeResponse(BaseModel):
    result: Literal["FP", "TP", "Incident"]
    reason: str
    similar_cases: list[dict] = Field(default_factory=list, description="RAG-retrieved past cases")


class FeedbackRequest(BaseModel):
    raw_log: str = Field(..., min_length=1)
    label: Literal["FP", "TP", "Incident"]
    analyst_comment: str = Field(default="", description="Optional analyst note")


class FeedbackResponse(BaseModel):
    status: str
    point_id: str

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

    # ── vLLM OpenAI-compatible async client ──
    llm_client = AsyncOpenAI(base_url=LLM_BASE_URL, api_key="not-needed")
    logger.info("LLM client initialised (base_url=%s).", LLM_BASE_URL)

    yield  # application runs

    # ── Cleanup ──
    if qdrant:
        qdrant.close()
    logger.info("Shutdown complete.")

# ───────────────────────── FastAPI App ───────────────────────────

app = FastAPI(
    title="SOC AI Triage API",
    description="Security Operations Center – AI-powered log triage with RAG feedback loop",
    version="1.0.0",
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
                    "analyst_comment": payload.get("analyst_comment", ""),
                }
            )
        return results
    except Exception:
        logger.exception("RAG search failed — continuing without history.")
        return []


def _build_prompt(raw_log: str, similar_cases: list[dict]) -> list[dict]:
    """
    Build the Chat Completions messages list.
    Includes RAG context when available, gracefully omits when not.
    """
    system_content = (
        "You are a senior SOC analyst AI. Your task is to triage a security log entry.\n"
        "Classify the log as exactly one of: FP (False Positive), TP (True Positive), or Incident.\n"
        "You MUST respond with ONLY a valid JSON object in this exact schema:\n"
        '{"result": "FP" | "TP" | "Incident", "reason": "<1-2 sentence explanation>"}\n'
        "Do NOT include any text outside the JSON object."
    )

    user_parts: list[str] = []

    # RAG context
    if similar_cases:
        user_parts.append("### Similar Past Cases (from analyst knowledge base):")
        for idx, case in enumerate(similar_cases, 1):
            user_parts.append(
                f"Case {idx} (similarity {case['score']}):\n"
                f"  Log: {case['raw_log']}\n"
                f"  Verdict: {case['label']}\n"
                f"  Analyst note: {case['analyst_comment']}"
            )
        user_parts.append("")  # blank line separator

    user_parts.append("### New Log Entry to Triage:")
    user_parts.append(raw_log)

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

    if result_val not in {"FP", "TP", "Incident"}:
        logger.warning("LLM returned unexpected result value: '%s'. Defaulting to TP.", result_val)
        result_val = "TP"

    return TriageResult(result=result_val, reason=reason_val)

# ───────────────────────── Endpoints ─────────────────────────────

@app.get("/health", tags=["ops"])
async def health_check():
    """Liveness / readiness probe."""
    return {"status": "healthy"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["triage"],
    summary="Triage a raw security log",
)
async def analyze_log(req: AnalyzeRequest):
    """
    1. Embed the raw log.
    2. Retrieve top-2 similar past cases from Qdrant (RAG).
    3. Construct a prompt and call the LLM via vLLM's Chat Completions API.
    4. Parse the structured JSON verdict and return it.
    """
    logger.info("Received /analyze request (%d chars).", len(req.raw_log))

    # Step 1 – embed
    vector = _embed(req.raw_log)

    # Step 2 – RAG retrieval
    similar_cases = _search_similar(vector, top_k=2)
    logger.info("RAG returned %d similar case(s).", len(similar_cases))

    # Step 3 – build prompt
    messages = _build_prompt(req.raw_log, similar_cases)

    # Step 4 – call LLM with JSON mode (guided decoding)
    try:
        chat_response = await llm_client.chat.completions.create(  # type: ignore[union-attr]
            model="fdtn-ai/Foundation-Sec-8B",
            messages=messages,
            temperature=0.1,
            max_tokens=256,
            extra_body={
                "guided_json": json.dumps(
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
            },
        )
    except Exception as exc:
        logger.exception("LLM call failed.")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM engine unreachable or returned error: {exc}",
        ) from exc

    raw_content = chat_response.choices[0].message.content or ""
    logger.debug("LLM raw response: %s", raw_content[:500])

    # Step 5 – parse
    triage = _parse_llm_response(raw_content)

    return AnalyzeResponse(
        result=triage.result,
        reason=triage.reason,
        similar_cases=similar_cases,
    )


@app.post(
    "/feedback",
    response_model=FeedbackResponse,
    tags=["feedback"],
    summary="Submit analyst feedback to the knowledge base",
)
async def submit_feedback(req: FeedbackRequest):
    """
    Embed the raw log and upsert a new point into Qdrant with the
    analyst-provided label and comment, enriching future RAG retrieval.
    """
    logger.info("Received /feedback — label=%s, comment=%s", req.label, req.analyst_comment[:80])

    vector = _embed(req.raw_log)
    point_id = str(uuid.uuid4())

    try:
        qdrant.upsert(  # type: ignore[union-attr]
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={
                        "raw_log": req.raw_log,
                        "label": req.label,
                        "analyst_comment": req.analyst_comment,
                    },
                )
            ],
        )
    except Exception as exc:
        logger.exception("Qdrant upsert failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Vector DB write failed: {exc}",
        ) from exc

    logger.info("Feedback stored — point_id=%s", point_id)
    return FeedbackResponse(status="stored", point_id=point_id)
