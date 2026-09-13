# Case Creation API Contract (v1.0)

> **Mục đích:** Tài liệu này mô tả chi tiết API endpoint cho phép các hệ thống bên ngoài (SOAR, SIEM, Automation Platform, n8n, Python Script...) **tạo case tự động** trong Fushion Center Case Management System thông qua API Key, chạy song song với tính năng tạo case thủ công qua UI.

---

## 🤖 Prompt mẫu cho AI Agent khi Vibe Code hệ thống bên ngoài

```markdown
Bạn là lập trình viên tích hợp hệ thống. Đọc kỹ API Contract này để tích hợp tạo case tự động vào Fushion Center Case Management.
- Endpoint: POST /api/v1/cases
- Auth: Header X-API-Key: <your_api_key>
- Trường bắt buộc: title (string), tenant (string — tên organization đã tồn tại trong hệ thống)
- Trường tùy chọn: severity (1-4), description, tags, assignee, tlp, pap, owner, flag, summary, case_template
- Đảm bảo bắt lỗi: 400 (thiếu trường/validation), 401 (API key không hợp lệ), 404 (org không tồn tại), 500 (lỗi server).
```

---

## 1. Thông số kết nối

### 1.1 Base URLs

| Môi trường | Base URL | Ghi chú |
|:---|:---|:---|
| **Local Dev** | `http://localhost:3001` | Backend Go chạy trực tiếp |
| **Docker Compose** | `http://backend:3001` | Khi gọi từ container khác cùng network |
| **LAN / Remote** | `http://<IP_SERVER>:3001` | Server trong mạng nội bộ / VPN |

### 1.2 Authentication

Endpoint tạo case hỗ trợ **hai phương thức xác thực** song song:

| Phương thức | Header | Dùng cho |
|:---|:---|:---|
| **API Key** | `X-API-Key: <key>` | SOAR, SIEM, Automation, Scripts |
| **API Key (Bearer)** | `Authorization: Bearer <key>` | Tương thích với OAuth2 clients |
| **JWT Token** | `Authorization: Bearer <jwt>` | Analyst qua UI (đã có sẵn) |

> **Lưu ý:** API Key được tạo và quản lý trong phần **Admin → API Keys** của hệ thống. Mỗi API Key được gắn với một user account và kế thừa permissions của user đó. User cần có permission `manageCase`.

---

## 2. Endpoint Tạo Case (`POST /api/v1/cases`)

- **Method:** `POST`
- **Path:** `/api/v1/cases`
- **Full URL:** `http://localhost:3001/api/v1/cases`
- **Headers:**
  ```http
  Content-Type: application/json
  Accept: application/json
  X-API-Key: <your_api_key>
  ```

### 2.1 Request Body Schema

| Trường | Kiểu | Bắt buộc | Mặc định | Ràng buộc | Mô tả |
|:---|:---|:---:|:---:|:---|:---|
| `title` | `string` | **Có** | — | `min_length >= 1` | Tiêu đề case. Ngắn gọn, mô tả rõ sự cố. |
| `tenant` | `string` | **Có** | — | Phải là org đã tồn tại | Tên Organization (tenant) quản lý case này. |
| `description` | `string` | Không | `""` | — | Mô tả chi tiết, có thể chứa raw log, IoC, context. |
| `severity` | `integer` | Không | `2` (Medium) | `1`–`4` | Độ nghiêm trọng: 1=Low, 2=Medium, 3=High, 4=Critical. |
| `tlp` | `integer` | Không | `2` | `0`–`3` | Traffic Light Protocol: 0=White, 1=Green, 2=Amber, 3=Red. |
| `pap` | `integer` | Không | `2` | `0`–`3` | Permissible Actions Protocol. |
| `owner` | `string` | Không | `""` | Login hợp lệ | Login của owner (người tạo/sở hữu). |
| `assignee` | `string` | Không | `""` | Login hợp lệ | Login của analyst được giao xử lý. |
| `tags` | `string[]` | Không | `[]` | — | Danh sách tags phân loại (vd: `["apt", "ransomware"]`). |
| `flag` | `boolean` | Không | `false` | — | Đánh dấu case quan trọng/ưu tiên. |
| `summary` | `string` | Không | `""` | — | Tóm tắt ngắn gọn về kết quả / hành động đã thực hiện. |
| `impact_status` | `string` | Không | `""` | Enum | Trạng thái tác động: `"WithImpact"`, `"NoImpact"`, `"NotApplicable"`. |
| `resolution_status` | `string` | Không | `""` | Enum | Trạng thái giải quyết: `"Indeterminate"`, `"FalsePositive"`, `"TruePositive"`, `"Other"`. |
| `case_template` | `string` | Không | `""` | Template name | Áp dụng template có sẵn (tên template chính xác). |
| `owning_organisation` | `string` | Không | `""` | Org name | Organization sở hữu case (multi-tenant). |
| `organisation_ids` | `string[]` | Không | `[]` | UUIDs | Danh sách IDs của các org được chia sẻ case. |

#### Ví dụ Request Body — Tối thiểu (chỉ trường bắt buộc):
```json
{
  "title": "Suspicious PowerShell execution on WKS-042",
  "tenant": "Default"
}
```

#### Ví dụ Request Body — Đầy đủ (SOAR integration):
```json
{
  "title": "[SOAR-AUTO] Cobalt Strike Beacon Detected — 192.168.1.55",
  "description": "Aug 22 14:33:12 wks-042 sysmon: ProcessCreate | powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcA...\nParent: explorer.exe | PID: 4892\nSource IP: 192.168.1.55 | Dest: 185.220.101.42:443",
  "severity": 4,
  "tlp": 2,
  "pap": 2,
  "owner": "soar_service",
  "assignee": "analyst_ha",
  "tags": ["cobalt-strike", "c2", "apt", "auto-created"],
  "flag": true,
  "tenant": "SOC-Team",
  "case_template": "Malware Incident Template"
}
```

---

### 2.2 Response Schema (Thành công — HTTP 201 Created)

Khi tạo case thành công, hệ thống trả về object Case đầy đủ:

| Trường | Kiểu | Mô tả |
|:---|:---|:---|
| `id` | `string` (UUID) | ID duy nhất của case trong hệ thống |
| `number` | `integer` | Số case tuần tự (hiển thị dạng `#1042`) |
| `title` | `string` | Tiêu đề case |
| `description` | `string` | Mô tả chi tiết |
| `severity` | `integer` | Độ nghiêm trọng (1–4) |
| `status` | `string` | Trạng thái ban đầu: `"Open"` |
| `tlp` | `integer` | TLP level |
| `pap` | `integer` | PAP level |
| `owner` | `string` | Login owner |
| `assignee` | `string` | Login assignee |
| `tags` | `string[]` | Danh sách tags |
| `flag` | `boolean` | Trạng thái đánh dấu |
| `tenant` | `string` | Tên organization |
| `created_at` | `string` | Timestamp ISO 8601 tạo case |
| `updated_at` | `string` | Timestamp ISO 8601 cập nhật gần nhất |
| `ai_assessment` | `object\|null` | Kết quả AI Triage (điền sau vài giây nếu SOC AI đang chạy) |

#### Ví dụ Response (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "number": 1042,
  "title": "[SOAR-AUTO] Cobalt Strike Beacon Detected — 192.168.1.55",
  "description": "Aug 22 14:33:12 wks-042 sysmon: ProcessCreate | powershell.exe ...",
  "severity": 4,
  "status": "Open",
  "tlp": 2,
  "pap": 2,
  "flag": true,
  "owner": "soar_service",
  "assignee": "analyst_ha",
  "tags": ["cobalt-strike", "c2", "apt", "auto-created"],
  "tenant": "SOC-Team",
  "created_at": "2026-09-12T14:33:15Z",
  "updated_at": "2026-09-12T14:33:15Z",
  "ai_assessment": null
}
```

> **Lưu ý về AI Triage tự động:** Ngay sau khi case được tạo, hệ thống sẽ tự động gọi SOC AI `/analyze` trong background. Kết quả sẽ được cập nhật vào trường `ai_assessment` trong vài giây đến vài phút, tùy độ phức tạp của log. Poll `GET /api/v1/cases/{id}` để lấy kết quả phân tích.

---

## 3. Error Responses

| HTTP Code | Tên lỗi | Nguyên nhân | Body | Hành động |
|:---:|:---|:---|:---|:---|
| **`400`** | Bad Request | `title` rỗng, `tenant` rỗng, hoặc trường không hợp lệ | `{"error": "...", "message": "tenant is required..."}` | Kiểm tra lại request body |
| **`401`** | Unauthorized | Thiếu API Key hoặc key không hợp lệ / hết hạn | `{"error": "Yêu cầu cung cấp API key"}` | Kiểm tra lại API Key |
| **`403`** | Forbidden | User không có permission `manageCase` | `{"error": "forbidden"}` | Gán permission đúng cho user |
| **`404`** | Not Found | `tenant` (organization) không tồn tại trong hệ thống | `{"error": "organisation does not exist: ..."}` | Tạo org trước hoặc kiểm tra lại tên |
| **`422`** | Unprocessable | Validation fail (ví dụ title quá ngắn) | `{"error": "...", "message": "..."}` | Xem chi tiết lỗi trong message |
| **`500`** | Internal Error | Lỗi database hoặc transaction | `{"error": "case create failed"}` | Liên hệ admin, thử lại sau |

#### Ví dụ Error Response (401):
```json
{
  "error": "Yêu cầu cung cấp API key"
}
```

#### Ví dụ Error Response (400 — thiếu tenant):
```json
{
  "error": "tenant is required and cannot be empty"
}
```

---

## 4. Code mẫu tích hợp sẵn sàng Copy-Paste

### 4.1 cURL

```bash
# Tạo case tối thiểu
curl -X POST "http://localhost:3001/api/v1/cases" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious login from unknown IP",
    "tenant": "Default"
  }'

# Tạo case đầy đủ từ SOAR
curl -X POST "http://localhost:3001/api/v1/cases" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "[SOAR-AUTO] Ransomware Activity Detected — WKS-088",
    "description": "Sysmon Event ID 11: FileCreate suspicious extension .locked\nSource: C:\\Users\\jdoe\\Documents\\*.locked\nParent Process: explorer.exe\nNetwork: 10.0.0.88 -> 185.220.101.42:443",
    "severity": 4,
    "tlp": 2,
    "pap": 2,
    "tags": ["ransomware", "auto-created", "soar"],
    "flag": true,
    "assignee": "analyst_ha",
    "tenant": "SOC-Team"
  }'
```

### 4.2 TypeScript / JavaScript (`fetch`)

```typescript
interface CreateCaseRequest {
  title: string;            // Bắt buộc
  tenant: string;           // Bắt buộc
  description?: string;
  severity?: 1 | 2 | 3 | 4; // 1=Low, 2=Medium, 3=High, 4=Critical
  tlp?: 0 | 1 | 2 | 3;
  pap?: 0 | 1 | 2 | 3;
  owner?: string;
  assignee?: string;
  tags?: string[];
  flag?: boolean;
  summary?: string;
  impact_status?: "WithImpact" | "NoImpact" | "NotApplicable";
  resolution_status?: "Indeterminate" | "FalsePositive" | "TruePositive" | "Other";
  case_template?: string;
}

interface CreateCaseResponse {
  id: string;
  number: number;
  title: string;
  description: string;
  severity: number;
  status: string;
  tlp: number;
  pap: number;
  flag: boolean;
  owner: string;
  assignee: string;
  tags: string[];
  tenant: string;
  created_at: string;
  updated_at: string;
  ai_assessment: object | null;
}

async function createCase(
  baseUrl: string,
  apiKey: string,
  payload: CreateCaseRequest,
): Promise<CreateCaseResponse> {
  const response = await fetch(`${baseUrl.replace(/\/+$/, "")}/api/v1/cases`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-API-Key": apiKey,
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const errJson = await response.json();
      detail = JSON.stringify(errJson);
    } catch {
      // ignore non-JSON error
    }
    throw new Error(`Failed to create case: ${detail}`);
  }

  return (await response.json()) as CreateCaseResponse;
}

// ── Ví dụ gọi hàm:
// const newCase = await createCase("http://localhost:3001", "sk-abc123...", {
//   title: "[SOAR] Cobalt Strike Beacon Detected",
//   description: "Raw log: ...",
//   severity: 4,
//   tags: ["apt", "c2"],
//   tenant: "Default",
// });
// console.log("Case created:", newCase.id, "#" + newCase.number);
```

### 4.3 Python (`httpx`)

```python
import httpx
from typing import Optional

def create_case(
    base_url: str,
    api_key: str,
    title: str,
    tenant: str,
    description: str = "",
    severity: int = 2,          # 1=Low, 2=Medium, 3=High, 4=Critical
    tlp: int = 2,
    pap: int = 2,
    tags: Optional[list] = None,
    flag: bool = False,
    assignee: str = "",
    timeout: float = 30.0,
) -> dict:
    """
    Tạo case mới trong Fushion Center Case Management thông qua API Key.

    Args:
        base_url: URL backend (vd: 'http://localhost:3001')
        api_key: API Key lấy từ Admin → API Keys
        title: Tiêu đề case (bắt buộc)
        tenant: Tên Organization (bắt buộc, phải tồn tại trong hệ thống)
        description: Mô tả chi tiết / raw log
        severity: 1=Low, 2=Medium, 3=High, 4=Critical
        ...

    Returns:
        dict với id, number, title, created_at, v.v.

    Raises:
        httpx.HTTPStatusError: khi server trả về mã lỗi 4xx/5xx
    """
    url = f"{base_url.rstrip('/')}/api/v1/cases"
    payload = {
        "title": title,
        "tenant": tenant,
        "description": description,
        "severity": severity,
        "tlp": tlp,
        "pap": pap,
        "tags": tags or [],
        "flag": flag,
        "assignee": assignee,
    }

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            url,
            json=payload,
            headers={
                "X-API-Key": api_key,
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()


# ── Ví dụ gọi hàm:
# new_case = create_case(
#     base_url="http://localhost:3001",
#     api_key="sk-abc123...",
#     title="[SOAR-AUTO] Malware detected on 192.168.1.50",
#     tenant="Default",
#     description="Sysmon EventID 1: powershell.exe -nop -w hidden ...",
#     severity=4,
#     tags=["malware", "auto-created"],
#     flag=True,
# )
# print(f"Case #{new_case['number']} created: {new_case['id']}")
```

### 4.4 n8n / Workflow Automation (HTTP Request Node)

```yaml
# Cấu hình n8n HTTP Request Node:
Method: POST
URL: http://backend:3001/api/v1/cases
Authentication: Header Auth
  Name: X-API-Key
  Value: {{ $env.FUSHION_API_KEY }}
Body:
  title: "[n8n] {{ $json.alert_name }}"
  description: "{{ $json.raw_log }}"
  severity: "{{ $json.severity_level }}"
  tenant: "Default"
  tags: ["n8n-auto", "{{ $json.source }}"]
```

---

## 5. Sau khi tạo case — Luồng tích hợp tiếp theo

Sau khi `POST /api/v1/cases` thành công và nhận về `case_id`, hệ thống tự động:

1. **AI Auto-Triage** (background): Gọi SOC AI `/analyze` với `description` làm log đầu vào → kết quả lưu vào `ai_assessment`.
2. **MISP Auto-Sync** (background): Nếu case chứa IOC có thể detect, tự động đồng bộ sang MISP.
3. **Custom Property Extraction** (background): Trích xuất các thuộc tính tùy chỉnh từ `description` bằng LLM.

**Poll kết quả AI:**
```bash
# Lấy case info (bao gồm ai_assessment sau khi AI xử lý xong)
curl -H "X-API-Key: YOUR_KEY" http://localhost:3001/api/v1/cases/{case_id}
```

**Kích hoạt Feedback Loop sau khi analyst xem xét:**
```bash
curl -X POST "http://localhost:3001/api/v1/soc/feedback" \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "raw_log": "<same log you sent in description>",
    "label": "TruePositive",
    "analyst_comment": "Confirmed C2 beacon via CobaltStrike malleable profile"
  }'
```

---

## 6. Checklist kiểm tra khi tích hợp

- [ ] **Tạo API Key:** Admin → API Keys → Generate Key → copy toàn bộ key (chỉ hiện 1 lần).
- [ ] **Gán permission:** User gắn với API Key phải có role/permission `manageCase`.
- [ ] **Tenant chính xác:** Giá trị `tenant` phải khớp chính xác với tên Organization trong hệ thống (case-sensitive).
- [ ] **Validate `title`:** Không gửi request nếu title rỗng hoặc chỉ có whitespace.
- [ ] **Xử lý 401:** Nếu nhận `401`, kiểm tra lại API Key — có thể đã bị xóa hoặc user bị khóa.
- [ ] **Xử lý 404:** Nếu nhận `404` với message `"organisation does not exist"`, tạo org trong Admin trước.
- [ ] **Poll AI result:** Sau 5–30 giây, poll `GET /api/v1/cases/{id}` để lấy `ai_assessment`.
- [ ] **Feedback Loop:** Sau khi analyst xác nhận kết quả AI, gửi feedback qua `POST /api/v1/soc/feedback` để train model.
