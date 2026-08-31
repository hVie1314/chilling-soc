# SOC AI Triage System

> AI-powered Security Operations Center log triage with a Retrieval-Augmented Generation (RAG) feedback loop.

A microservices architecture that uses a cybersecurity-tuned LLM (**Foundation-Sec-8B**) to automatically classify raw security logs as **False Positive**, **True Positive**, or **Incident** — and learns from analyst corrections over time.

The embedding model (`nomic-ai/nomic-embed-text-v1.5`) supports an **8192-token context window**, ensuring long log entries — including trailing Base64 payloads, RCE strings, and encoded parameters — are fully captured without truncation. Analyst feedback is persisted to host-mounted volumes, so RAG memories survive container rebuilds and restarts.

---

## Architecture

The system supports two deployment modes. The **backend code is LLM-provider agnostic** — switching between development and production is purely a configuration change.

### Development (Ollama on Windows)

No NVIDIA GPU, CUDA, or NVIDIA Container Toolkit required.

```
                    Windows Host
┌─────────────────────────────────────────────────┐
│                                                 │
│  Ollama :11434                                  │
│      └── Foundation-Sec-8B Q4_K_M               │
│                                                 │
│──────────────── Docker Desktop ────────────────│
│                                                 │
│  ┌──────────┐       ┌──────────────┐            │
│  │ web-ui   │──────►│ api-backend  │            │
│  │  :8501   │       │    :8080     │            │
│  └──────────┘       └──────┬───────┘            │
│                             │                    │
│                   ┌─────────┴─────────┐          │
│                   ▼                   ▼          │
│             Ollama Host          Qdrant          │
│       host.docker.internal      :6333            │
│              :11434                              │
└─────────────────────────────────────────────────┘
```

| Container      | Image / Build              | Purpose                          | Port  |
|----------------|----------------------------|----------------------------------|-------|
| `vector-db`    | `qdrant/qdrant:latest`     | Vector store for RAG knowledge   | 6333  |
| `api-backend`  | `./api-backend/Dockerfile` | FastAPI orchestrator              | 8080  |
| `web-ui`       | `./web-ui/Dockerfile`      | Streamlit analyst interface       | 8501  |

### Production (vLLM on GPU server)

```
┌────────────────┐     ┌──────────────────┐     ┌───────────────┐
│   web-ui       │────►│   api-backend    │────►│  llm-engine   │
│  (Streamlit)   │     │    (FastAPI)      │     │    (vLLM)     │
│   :8501        │     │    :8080          │     │   :8000       │
└────────────────┘     └──────┬───────────┘     └───────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │  vector-db   │
                       │  (Qdrant)    │
                       │  :6333       │
                       └──────────────┘
```

| Container      | Image / Build              | Purpose                          | Port  |
|----------------|----------------------------|----------------------------------|-------|
| `vector-db`    | `qdrant/qdrant:latest`     | Vector store for RAG knowledge   | 6333  |
| `llm-engine`   | `vllm/vllm-openai:latest`  | Serves Foundation-Sec-8B (GPU)   | 8000  |
| `api-backend`  | `./api-backend/Dockerfile` | FastAPI orchestrator              | 8080  |
| `web-ui`       | `./web-ui/Dockerfile`      | Streamlit analyst interface       | 8501  |

---

## Local Development Setup (Windows + Ollama)

### Prerequisites

| Dependency      | Notes                                    |
|-----------------|------------------------------------------|
| Docker Desktop  | ≥ 24.x, with Compose v2                 |
| Ollama          | Installed natively on Windows            |
| ~8 GB free RAM  | For the Q4_K_M quantized model           |

> **Note:** NVIDIA GPU, CUDA, and NVIDIA Container Toolkit are **NOT** required for local development. Ollama runs natively on the Windows host and can use CPU inference.

### 1. Install Ollama

Download and install from [ollama.com](https://ollama.com/download).

Verify installation:

```powershell
ollama --version
```

### 2. Create the Local Model

The repository includes a `Modelfile` that wraps the instruction-tuned Foundation-Sec-8B GGUF with the correct Llama 3.1 chat template.

> **⚠️ Important:** The official `fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF` is a **base** (pretrained) model that does NOT support chat. The `Modelfile` uses the community **instruct** GGUF (`mradermacher/Foundation-Sec-8B-Instruct-GGUF`) with proper chat template and stop tokens.

```powershell
# From the repository root:
ollama create Foundation-Sec-8B-local -f Modelfile
```

This downloads the instruct GGUF (~4.9 GB) and creates a local model with the correct template.

Verify the model is available:

```powershell
ollama list
```

Test it:

```powershell
ollama run Foundation-Sec-8B-local "Hello. Reply with: OK"
```

### 3. Configure Environment

A `.env` file pre-configured for development is included. Review it:

```powershell
Get-Content .env
```

For reference, copy `.env.example` if you need to customize:

```powershell
Copy-Item .env.example .env
```

> **⚠️ Do not commit `.env` to version control.** It is already in `.gitignore`.

### 4. Build & Launch

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

> **First run** will take several minutes as it downloads the embedding model (~270 MB) and builds Docker images. Subsequent starts are fast.

### 5. Monitor Startup

```powershell
# Watch all logs
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f

# Watch only the backend
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f api-backend
```

Wait for the backend to show:
```
soc-api-backend  | INFO:     Uvicorn running on http://0.0.0.0:8080
```

### 6. Access the UI

Open your browser to:

```
http://localhost:8501
```

### 7. Verify Connectivity

Test that the backend can reach Ollama through Docker:

```powershell
# Check health (includes LLM connectivity status)
curl http://localhost:8080/health

# Or from inside the container:
docker exec soc-api-backend curl -s http://host.docker.internal:11434/v1/models
```

### 8. Stopping

```powershell
# Stop Docker containers (Qdrant data in ./qdrant_data is preserved)
docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Ollama continues running on the host; stop it via system tray or:
# taskkill /IM ollama.exe /F
```

---

## Production Setup (vLLM + NVIDIA GPU)

### Prerequisites

| Dependency                  | Version   | Install Guide                                                                 |
|-----------------------------|-----------|-------------------------------------------------------------------------------|
| Docker Engine               | ≥ 24.x    | https://docs.docker.com/engine/install/                                       |
| Docker Compose              | ≥ 2.20    | Bundled with Docker Desktop; standalone: `apt install docker-compose-plugin`  |
| NVIDIA Driver               | ≥ 535     | `nvidia-smi` to verify                                                        |
| NVIDIA Container Toolkit    | ≥ 1.14    | https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html |
| NVIDIA GPU                  | ≥ 16 GB   | 24 GB recommended for Foundation-Sec-8B at full precision                     |

### 1. Verify GPU Setup

```bash
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

### 2. Configure `.env` for Production

```bash
cat > .env << 'EOF'
HF_TOKEN=hf_your_actual_token_here
LLM_BASE_URL=http://llm-engine:8000/v1
LLM_MODEL=fdtn-ai/Foundation-Sec-8B
EOF
```

> **⚠️ Do not commit `.env` to version control.**

### 3. Build & Launch with vLLM

```bash
docker compose --profile prod up --build -d
```

> **First run** will take 10-30 minutes as it downloads Foundation-Sec-8B (~16 GB) into `./model_cache/`.

### 4. Monitor

```bash
docker compose logs -f llm-engine
```

Wait for:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 5. Access the UI

```
http://localhost:8501
```

---

## Usage

### Analyze a Log

1. Paste a raw security log into the text area
2. Click **🔍 Analyze**
3. The AI returns a verdict: **FP**, **TP**, or **Incident** with reasoning
4. If similar past cases exist in the knowledge base, they are shown below the result

### Submit Feedback

1. After analysis, review the verdict
2. Select the correct label from the dropdown (or confirm the AI's label)
3. Add an optional analyst comment
4. Click **💾 Save to Knowledge Base**
5. The feedback is vectorized and stored in Qdrant — future analyses will retrieve it as RAG context

### Example Logs to Try

```
Aug 22 14:33:12 fw01 kernel: DROP IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.0.5 PROTO=TCP SPT=44123 DPT=443 LEN=52 WINDOW=65535 SYN
```

```json
{"timestamp":"2026-08-22T07:21:00Z","rule":"ET SCAN Nmap Scripting Engine User-Agent Detected","src_ip":"198.51.100.10","dst_ip":"10.0.0.25","proto":"TCP","dst_port":80,"severity":2}
```

```
CEF:0|SecurityVendor|SecurityProduct|1.0|100|Malware Detected|10|src=192.168.1.50 dst=10.0.0.1 act=blocked filePath=/tmp/payload.exe fileHash=a1b2c3d4e5f6
```

---

## Data Flow

```
Raw Security Log
      ↓
Embedding (nomic-embed-text-v1.5)
      ↓
Qdrant Retrieval (similar past cases)
      ↓
RAG Context + Prompt
      ↓
Foundation-Sec-8B (Ollama / vLLM)
      ↓
FP / TP / Incident verdict
      ↓
Analyst Feedback
      ↓
Qdrant (persisted)
      ↓
Future RAG Retrieval
```

---

## API Reference

### `POST /analyze`

Triage a raw security log.

**Request:**
```json
{
  "raw_log": "Aug 22 14:33:12 fw01 kernel: DROP IN=eth0 ..."
}
```

**Response:**
```json
{
  "result": "FP",
  "reason": "This is a routine firewall drop of an external scan on port 443, matching known benign scanner IPs.",
  "similar_cases": [
    {
      "score": 0.8712,
      "raw_log": "...",
      "label": "FP",
      "analyst_comment": "Known Shodan scanner"
    }
  ]
}
```

### `POST /feedback`

Store analyst feedback into the knowledge base.

**Request:**
```json
{
  "raw_log": "...",
  "label": "FP",
  "analyst_comment": "Known scanner IP from Shodan"
}
```

**Response:**
```json
{
  "status": "stored",
  "point_id": "a1b2c3d4-..."
}
```

### `GET /health`

Liveness / readiness probe with dependency status.

**Response:**
```json
{
  "status": "healthy",
  "qdrant": "connected",
  "llm": "connected",
  "llm_models": ["hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF:Q4_K_M"]
}
```

---

## File Structure

```
soc-ai-triage/
├── docker-compose.yml          # Base stack (vector-db, api-backend, web-ui; llm-engine under prod profile)
├── docker-compose.dev.yml      # Development override (Ollama on Windows host)
├── Modelfile                   # Ollama Modelfile (Foundation-Sec-8B-Instruct + Llama 3.1 template)
├── .env                        # Active configuration (not committed)
├── .env.example                # Template with all supported variables
├── .gitignore
├── README.md
│
├── api-backend/
│   ├── Dockerfile              # Python 3.11 + sentence-transformers + einops
│   ├── requirements.txt        # FastAPI, openai, qdrant-client, einops, etc.
│   └── main.py                 # Async FastAPI: /analyze, /feedback, /health
│
├── web-ui/
│   ├── Dockerfile              # Python 3.11 + Streamlit
│   ├── requirements.txt        # streamlit, httpx
│   └── app.py                  # Analyst triage UI
│
├── qdrant_data/                # (auto-created) persistent Qdrant storage
└── model_cache/                # (auto-created) cached HF model weights (production)
```

---

## Configuration Reference

All configuration is via environment variables. Set them in `.env` or in the compose files.

| Variable           | Container     | Dev Default                                                | Prod Default                         | Description                              |
|--------------------|---------------|------------------------------------------------------------|--------------------------------------|------------------------------------------|
| `QDRANT_HOST`      | api-backend   | `vector-db`                                                | `vector-db`                          | Qdrant hostname                          |
| `QDRANT_PORT`      | api-backend   | `6333`                                                     | `6333`                               | Qdrant REST port                         |
| `LLM_BASE_URL`     | api-backend   | `http://host.docker.internal:11434/v1`                     | `http://llm-engine:8000/v1`          | OpenAI-compatible LLM endpoint           |
| `LLM_MODEL`        | api-backend   | `Foundation-Sec-8B-local`                                  | `fdtn-ai/Foundation-Sec-8B`          | Model name for chat completions          |
| `COLLECTION_NAME`  | api-backend   | `soc_knowledge_base`                                       | `soc_knowledge_base`                 | Qdrant collection name                   |
| `EMBEDDING_MODEL`  | api-backend   | `nomic-ai/nomic-embed-text-v1.5`                           | `nomic-ai/nomic-embed-text-v1.5`     | Sentence-transformer model (8192 tokens) |
| `HF_TOKEN`         | llm-engine    | *(not needed)*                                             | *(required for gated models)*        | Hugging Face token                       |
| `API_BACKEND_URL`  | web-ui        | `http://api-backend:8080`                                  | `http://api-backend:8080`            | Backend URL for Streamlit                |

---

## Troubleshooting

### Development (Ollama)

| Issue                                    | Solution                                                                              |
|------------------------------------------|---------------------------------------------------------------------------------------|
| Ollama not found                         | Install from [ollama.com](https://ollama.com/download), verify with `ollama --version`|
| Model not loaded                         | Run `ollama run hf.co/fdtn-ai/Foundation-Sec-8B-Q4_K_M-GGUF:Q4_K_M`                 |
| Backend can't reach Ollama               | Ensure Ollama is running; test: `curl http://localhost:11434/v1/models` from host      |
| `host.docker.internal` not resolving     | Update Docker Desktop; `extra_hosts` in dev compose provides fallback                  |
| Slow inference                           | Expected with CPU-only; Q4_K_M 8B model takes ~30-60s per response on CPU             |
| Qdrant connection refused                | Wait for health check; run `docker compose ps` to verify it's healthy                 |

### Production (vLLM)

| Issue                                    | Solution                                                                              |
|------------------------------------------|---------------------------------------------------------------------------------------|
| `llm-engine` OOM killed                  | Reduce `--max-model-len` to `2048` in `docker-compose.yml`                            |
| `llm-engine` stuck downloading           | Check `docker compose logs llm-engine`; ensure `HF_TOKEN` is set for gated models    |
| GPU not detected in container            | Run `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi`       |
| First `/analyze` call slow               | Normal — vLLM compiles CUDA graphs on first inference; subsequent calls are faster     |

---

## Stopping the System

### Development

```powershell
# Stop Docker containers (data in ./qdrant_data is preserved)
docker compose -f docker-compose.yml -f docker-compose.dev.yml down

# Stop and delete persistent data
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
Remove-Item -Recurse -Force qdrant_data
```

### Production

```bash
# Stop all containers (data in ./qdrant_data and ./model_cache is preserved)
docker compose --profile prod down

# Stop and delete persistent data
docker compose --profile prod down
rm -rf qdrant_data model_cache
```

---

## License

Internal use. Adjust as needed.
