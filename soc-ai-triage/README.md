# SOC AI Triage System

> AI-powered Security Operations Center log triage with a Retrieval-Augmented Generation (RAG) feedback loop.

A 4-container microservices architecture that uses a cybersecurity-tuned LLM (**Foundation-Sec-8B**) to automatically classify raw security logs as **False Positive**, **True Positive**, or **Incident** — and learns from analyst corrections over time.

The embedding model (`nomic-ai/nomic-embed-text-v1.5`) supports an **8192-token context window**, ensuring long log entries — including trailing Base64 payloads, RCE strings, and encoded parameters — are fully captured without truncation. Analyst feedback is persisted to host-mounted volumes, so RAG memories survive container rebuilds and restarts.

---

## Architecture

```
┌────────────────┐     ┌──────────────────┐     ┌───────────────┐
│   web-ui       │────▶│   api-backend    │────▶│  llm-engine   │
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

## Prerequisites

### 1. Hardware

- **NVIDIA GPU** with ≥ 16 GB VRAM (24 GB recommended for Foundation-Sec-8B at full precision)
- At least **32 GB system RAM**
- **50+ GB free disk** for model weights and Docker images

### 2. Software

| Dependency                  | Version   | Install Guide                                                                 |
|-----------------------------|-----------|-------------------------------------------------------------------------------|
| Docker Engine               | ≥ 24.x    | https://docs.docker.com/engine/install/                                       |
| Docker Compose              | ≥ 2.20    | Bundled with Docker Desktop; standalone: `apt install docker-compose-plugin`  |
| NVIDIA Driver               | ≥ 535     | `nvidia-smi` to verify                                                        |
| NVIDIA Container Toolkit    | ≥ 1.14    | https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html |

### 3. Verify NVIDIA Container Toolkit

```bash
# Should show your GPU(s)
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

If this fails, install/configure the toolkit:

```bash
# Ubuntu / Debian
distribution=$(. /etc/os-release; echo $ID$VERSION_ID)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

### 4. HuggingFace Token

`fdtn-ai/Foundation-Sec-8B` is a **gated model**. You need a HuggingFace **Read** token to download it:

1. Create a free account at [huggingface.co](https://huggingface.co/join)
2. Go to the [Foundation-Sec-8B model page](https://huggingface.co/fdtn-ai/Foundation-Sec-8B) and accept the license/access terms
3. Generate a **Read** token at [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
4. You will add this token to a `.env` file in the next section

---

## Quick Start

### 1. Clone & Navigate

```bash
cd soc-ai-triage
```

### 2. Create `.env` File

Create a `.env` file in the project root with your HuggingFace token:

```bash
# Linux / macOS
echo 'HF_TOKEN=hf_your_actual_token' > .env
```

```powershell
# Windows PowerShell
Set-Content -Path .env -Value 'HF_TOKEN=hf_your_actual_token'
```

A template `.env` file is already included — just replace the placeholder value.

> **⚠️ Do not commit `.env` to version control.** Add it to `.gitignore`.

### 3. Build & Launch

```bash
docker compose up --build -d
```

> **First run** will take 10-30 minutes as it:
> - Downloads the Foundation-Sec-8B model weights (~16 GB) into `./model_cache/`
> - Downloads the `nomic-ai/nomic-embed-text-v1.5` embedding model (~270 MB)
> - Builds the backend and frontend Docker images
>
> Subsequent starts are fast — model weights and Qdrant data are persisted on the host.

### 4. Monitor Startup

```bash
# Watch all logs
docker compose logs -f

# Watch only the LLM engine loading
docker compose logs -f llm-engine
```

Wait for the `llm-engine` to show:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 5. Access the UI

Open your browser to:

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

Liveness probe.

---

## File Structure

```
soc-ai-triage/
├── docker-compose.yml          # Full stack orchestration
├── .env                        # HF_TOKEN (not committed to git)
├── README.md                   # This file
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
└── model_cache/                # (auto-created) cached HF model weights
```

---

## Configuration Reference

All configuration is via environment variables set in `docker-compose.yml`:

| Variable           | Container     | Default                              | Description                      |
|--------------------|---------------|--------------------------------------|----------------------------------|
| `QDRANT_HOST`      | api-backend   | `vector-db`                          | Qdrant hostname                  |
| `QDRANT_PORT`      | api-backend   | `6333`                               | Qdrant REST port                 |
| `LLM_BASE_URL`     | api-backend   | `http://llm-engine:8000/v1`          | vLLM OpenAI-compatible endpoint  |
| `COLLECTION_NAME`  | api-backend   | `soc_knowledge_base`                 | Qdrant collection name           |
| `EMBEDDING_MODEL`  | api-backend   | `nomic-ai/nomic-embed-text-v1.5`     | Sentence-transformer model (8192 tokens) |
| `HF_TOKEN`         | llm-engine    | *(empty)*                            | Hugging Face token (if needed)   |
| `API_BACKEND_URL`  | web-ui        | `http://api-backend:8080`            | Backend URL for Streamlit        |

---

## Troubleshooting

| Issue                                | Solution                                                                              |
|--------------------------------------|---------------------------------------------------------------------------------------|
| `llm-engine` OOM killed              | Reduce `--max-model-len` to `2048` in `docker-compose.yml`                            |
| `llm-engine` stuck downloading       | Check `docker compose logs llm-engine`; ensure `HF_TOKEN` is set for gated models    |
| GPU not detected in container        | Run `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi`       |
| Qdrant connection refused            | Wait for health check; run `docker compose ps` to verify it's healthy                 |
| First `/analyze` call slow           | Normal — vLLM compiles CUDA graphs on first inference; subsequent calls are faster     |
| Backend returns 502                  | LLM is still loading; wait for `llm-engine` health check to pass                      |

---

## Stopping the System

```bash
# Stop all containers (data in ./qdrant_data and ./model_cache is preserved)
docker compose down

# Stop and delete persistent data
docker compose down
rm -rf qdrant_data model_cache
```

---

## License

Internal use. Adjust as needed.
