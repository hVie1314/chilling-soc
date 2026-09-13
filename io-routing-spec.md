# SOC AI Triage System — I/O Routing & Action Dispatch Specification (`io-routing-spec.md`)

**Version:** 1.0.0  
**Status:** Canonical Reference Architecture  
**Target Systems:** `api-backend` (FastAPI Orchestrator), `web-ui` (Streamlit Dashboard), SIEM/EDR, Case Management (e.g. TheHive, Jira), SOAR (e.g. Cortex XSOAR, Splunk SOAR, Shuffle)

---

## 1. Executive Summary & Philosophy

The SOC AI Triage System acts as an autonomous tier-1 log triage engine. To operate reliably in hybrid environments (where both interactive human analysts and automated event pipelines submit alerts), the system must decouple:
1. **Input Ingestion Source**: Where the log originated (`web_ui` vs `api_siem`).
2. **AI Triage & Context Retrieval**: Vector embedding, Qdrant RAG past-verdict retrieval, and LLM classification (`TruePositive`, `FalsePositive`, `Benign`, `Suspicious`).
3. **Dynamic Action Routing**: Downstream dispatch rules determined by the **input source**, the **AI verdict**, and the **persisted routing policies**.

```
                       ┌─────────────────────────┐
                       │      INPUT SOURCES      │
                       └────────────┬────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
        ┌──────────────────┐                ┌──────────────────┐
        │     Web UI       │                │     API SIEM     │
        │ (Analyst Portal) │                │ (Automated Stream│
        └─────────┬────────┘                └─────────┬────────┘
                  │ [source: "web_ui"]                │ [source: "api_siem"]
                  └─────────────────┬─────────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │      FastAPI Orchestrator     │
                    │   • Persist case to SQLite    │
                    │   • Vector embed (nomic-1.5)  │
                    │   • RAG search (Qdrant)       │
                    │   • LLM Triage (Foundation-8B)│
                    └───────────────┬───────────────┘
                                    │ Verdict: TP / FP / Benign / Suspicious
                                    ▼
                    ┌───────────────────────────────┐
                    │    Action Routing Engine      │
                    │  (Evaluates Policy by Source) │
                    └───────────────┬───────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   HTTP Verdict   │      │ Case Management  │      │  SOAR Auto-Close │
│ (Caller Return)  │      │ (Push Incident)  │      │ (Dismiss FP)     │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

---

## 2. Input / Output Routing Matrix

The backend enforces dynamic routing policies based on the alert's `source`. The matrix below defines the standard and configurable execution behaviors:

| Input Source (`source`) | AI Verdict | Allowed Downstream Destinations | Default Policy | Configuration Flag |
| :--- | :--- | :--- | :--- | :--- |
| **`web_ui`** (Analyst) | `TruePositive`, `Suspicious` | • `web_ui` (Direct HTTP JSON)<br>• `case_management` (Webhook POST) | `web_ui` only (Analyst reviews before pushing) | `routing.web_source.enable_case_mgmt_push` |
| **`web_ui`** (Analyst) | `FalsePositive`, `Benign` | • `web_ui` (Direct HTTP JSON)<br>• `soar_edge` (Auto-close POST) | `web_ui` only (Guard against accidental dismissal during testing) | `routing.web_source.enable_soar_autoclose` |
| **`api_siem`** (Automated) | `TruePositive`, `Suspicious` | • `api_siem` (Direct HTTP 200)<br>• `case_management` (Webhook POST)<br>• SQLite Audit Trail | `api_siem` + `case_management` | `routing.api_source.enable_case_mgmt_push` |
| **`api_siem`** (Automated) | `FalsePositive`, `Benign` | • `api_siem` (Direct HTTP 200)<br>• `soar_edge` (Auto-close POST)<br>• SQLite Audit Trail | `api_siem` + `soar_edge` | `routing.api_source.enable_soar_autoclose` |
| **`dry_run` Mode** (Any) | Any | • Direct HTTP Response Only<br>• Side-effects bypassed | No external API calls made | `routing.global.dry_run` |

### Key Policy Principles:
1. **Human-in-the-Loop Safety**: By default, logs submitted via `web_ui` should **not** fire destructive SOAR auto-close actions unless explicitly enabled by an admin toggle.
2. **Automated SIEM Autonomy**: Alerts originating from `api_siem` automatically route based on verdicts to save tier-1 SOC analyst time.
3. **Execution Receipts**: Every call to `/analyze` MUST return a list of `actions_dispatched` so the caller (frontend or automated pipeline) knows exactly what secondary systems were triggered.

---

## 3. Configuration State Schema (`system_settings`)

To eliminate ephemeral Streamlit session bugs, all system configurations must be persisted in SQLite and managed via FastAPI endpoints (`GET /config`, `PUT /config`).

### 3.1 JSON Schema Specification

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "SocSystemConfig",
  "type": "object",
  "properties": {
    "routing": {
      "type": "object",
      "properties": {
        "web_source": {
          "type": "object",
          "properties": {
            "enable_case_mgmt_push": { "type": "boolean", "default": false },
            "enable_soar_autoclose": { "type": "boolean", "default": false }
          },
          "required": ["enable_case_mgmt_push", "enable_soar_autoclose"]
        },
        "api_source": {
          "type": "object",
          "properties": {
            "enable_case_mgmt_push": { "type": "boolean", "default": true },
            "enable_soar_autoclose": { "type": "boolean", "default": true }
          },
          "required": ["enable_case_mgmt_push", "enable_soar_autoclose"]
        },
        "global": {
          "type": "object",
          "properties": {
            "dry_run": { "type": "boolean", "default": false },
            "min_trust_score_for_autoclose": { "type": "integer", "minimum": 1, "maximum": 5, "default": 1 }
          },
          "required": ["dry_run", "min_trust_score_for_autoclose"]
        }
      },
      "required": ["web_source", "api_source", "global"]
    },
    "destinations": {
      "type": "object",
      "properties": {
        "case_management": {
          "type": "object",
          "properties": {
            "webhook_url": { "type": "string", "format": "uri" },
            "auth_type": { "type": "string", "enum": ["none", "bearer", "api_key", "basic"] },
            "api_key": { "type": "string" },
            "timeout_seconds": { "type": "number", "default": 10.0 }
          },
          "required": ["webhook_url", "auth_type"]
        },
        "soar_edge": {
          "type": "object",
          "properties": {
            "api_url": { "type": "string", "format": "uri" },
            "auth_type": { "type": "string", "enum": ["none", "bearer", "api_key", "basic"] },
            "api_key": { "type": "string" },
            "timeout_seconds": { "type": "number", "default": 10.0 }
          },
          "required": ["api_url", "auth_type"]
        }
      },
      "required": ["case_management", "soar_edge"]
    }
  },
  "required": ["routing", "destinations"]
}
```

### 3.2 Pydantic Models for FastAPI

```python
from typing import Literal, Optional
from pydantic import BaseModel, Field, HttpUrl

AuthType = Literal["none", "bearer", "api_key", "basic"]

class SourceRoutingConfig(BaseModel):
    enable_case_mgmt_push: bool = False
    enable_soar_autoclose: bool = False

class GlobalRoutingConfig(BaseModel):
    dry_run: bool = False
    min_trust_score_for_autoclose: int = Field(default=1, ge=1, le=5)

class RoutingConfig(BaseModel):
    web_source: SourceRoutingConfig = Field(default_factory=lambda: SourceRoutingConfig(enable_case_mgmt_push=False, enable_soar_autoclose=False))
    api_source: SourceRoutingConfig = Field(default_factory=lambda: SourceRoutingConfig(enable_case_mgmt_push=True, enable_soar_autoclose=True))
    global_: GlobalRoutingConfig = Field(default_factory=GlobalRoutingConfig, alias="global")

class DestinationEndpoint(BaseModel):
    url: str = Field(default="", description="Endpoint URL")
    auth_type: AuthType = Field(default="none")
    api_key: str = Field(default="", description="API Key or Bearer Token (masked on read)")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)

class DestinationsConfig(BaseModel):
    case_management: DestinationEndpoint = Field(default_factory=DestinationEndpoint)
    soar_edge: DestinationEndpoint = Field(default_factory=DestinationEndpoint)

class SystemSettings(BaseModel):
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    destinations: DestinationsConfig = Field(default_factory=DestinationsConfig)
```

---

## 4. API Ingestion & Response Specifications

### 4.1 `POST /analyze` (Enhanced Request & Response)

#### Request Payload (`AnalyzeRequest`)
```json
{
  "alert_id": "ALERT-2026-09-0012",
  "source": "web_ui",
  "events": [
    "Aug 22 14:33:12 fw01 kernel: DROP IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.0.5 PROTO=TCP DPT=443",
    "Aug 22 14:33:15 fw01 kernel: ACCEPT IN=eth1 OUT= SRC=10.0.0.10 DST=10.0.0.5 PROTO=TCP DPT=22"
  ],
  "routing_overrides": {
    "force_case_push": false,
    "force_soar_close": false
  }
}
```

#### Response Payload (`AnalyzeResponse`)
```json
{
  "alert_id": "ALERT-2026-09-0012",
  "result": "TruePositive",
  "reason": "Phát hiện lưu lượng truy cập trái phép qua SSH ngay sau khi kết nối HTTPS bị chặn từ dải IP lạ.",
  "similar_cases": [
    {
      "score": 0.9412,
      "raw_log": "Aug 22 14:33:15 fw01 kernel: ACCEPT...",
      "label": "TruePositive",
      "comment": "Brute-force SSH thành công sau reconnaissance",
      "trust_score": 4
    }
  ],
  "actions_dispatched": [
    {
      "destination": "case_management",
      "status": "success",
      "timestamp": "2026-09-05T11:00:00Z",
      "http_status": 201,
      "details": "Created Ticket #CASE-8841"
    }
  ]
}
```

---

## 5. Backend Dynamic Routing Engine Architecture

### 5.1 SQLite Configuration Persistence

A dedicated `system_config` table in the existing SQLite database (`/app/data/soc_triage.db`):

```sql
CREATE TABLE IF NOT EXISTS system_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
```

### 5.2 Dynamic Dispatch Logic Flow

```python
async def route_actions(
    alert_id: str,
    events: list[str],
    triage: TriageResult,
    source: Literal["web_ui", "api_siem"],
    config: SystemSettings
) -> list[ActionReceipt]:
    receipts: list[ActionReceipt] = []

    # 1. Check Global Dry Run
    if config.routing.global_.dry_run:
        logger.info("[ROUTING] Dry-run enabled. Skipping all side effects.")
        return [ActionReceipt(destination="all", status="dry_run_skipped", details="Dry run active")]

    # 2. Select Source Policy
    policy = (
        config.routing.web_source
        if source == "web_ui"
        else config.routing.api_source
    )

    # 3. Route: TruePositive / Suspicious -> Case Management
    if triage.result in ("TruePositive", "Suspicious"):
        if policy.enable_case_mgmt_push:
            receipt = await dispatch_to_case_management(
                endpoint=config.destinations.case_management,
                alert_id=alert_id,
                events=events,
                verdict=triage.result,
                reason=triage.reason,
            )
            receipts.append(receipt)
        else:
            logger.info("[ROUTING] Case Management push disabled for source=%s", source)

    # 4. Route: FalsePositive / Benign -> SOAR Auto-Close
    elif triage.result in ("FalsePositive", "Benign"):
        if policy.enable_soar_autoclose:
            receipt = await trigger_soar_edge_extension_close(
                endpoint=config.destinations.soar_edge,
                alert_id=alert_id,
                verdict=triage.result,
                reason=triage.reason,
            )
            receipts.append(receipt)
        else:
            logger.info("[ROUTING] SOAR auto-close disabled for source=%s", source)

    return receipts
```

### 5.3 Production HTTP Dispatchers (`httpx.AsyncClient`)

```python
async def dispatch_to_case_management(
    endpoint: DestinationEndpoint,
    alert_id: str,
    events: list[str],
    verdict: str,
    reason: str,
) -> ActionReceipt:
    if not endpoint.url:
        return ActionReceipt(destination="case_management", status="skipped", details="No URL configured")

    headers = {"Content-Type": "application/json"}
    if endpoint.auth_type == "bearer" and endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    elif endpoint.auth_type == "api_key" and endpoint.api_key:
        headers["X-API-Key"] = endpoint.api_key

    payload = {
        "alert_id": alert_id,
        "events": events,
        "verdict": verdict,
        "triage_summary": reason,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=endpoint.timeout_seconds) as client:
            resp = await client.post(endpoint.url, json=payload, headers=headers)
            resp.raise_for_status()
            return ActionReceipt(
                destination="case_management",
                status="success",
                http_status=resp.status_code,
                details=resp.text[:200],
            )
    except Exception as exc:
        logger.error("Failed to push case to Case Management: %s", exc)
        return ActionReceipt(
            destination="case_management",
            status="failed",
            error=str(exc),
        )
```

---

## 6. Streamlit Settings UI Implementation Blueprint

The `⚙️ System Config` tab in `web-ui/app.py` must be upgraded from ephemeral text boxes to an interactive management panel that loads and writes to `GET /config` and `PUT /config`:

1. **Routing Matrix Editor**:
   - Two distinct visual cards:
     - **🌐 Web UI Source Rules**: Checkbox for `Push TruePositive to Case Management`, Checkbox for `Auto-close FalsePositive in SOAR`.
     - **🤖 SIEM / API Stream Rules**: Checkbox for `Push TruePositive to Case Management`, Checkbox for `Auto-close FalsePositive in SOAR`.
   - Global dry-run master toggle switch (`st.toggle("Global Dry Run Mode")`).
2. **Secure Destination Inputs**:
   - `Case Management Webhook URL` with Auth Type selection (`none`, `bearer`, `api_key`).
   - Password-masked text input (`type="password"`) for API Key / Bearer token.
   - `SOAR Edge API URL` with Auth Type selection and password-masked API Key input.
3. **Save & Sync**:
   - On clicking `💾 Save Configuration`, triggers `PUT http://api-backend:8080/config`.
   - Displays a success banner confirming persistent storage in SQLite.
