"""
integration.py
==============
Middleware / Integration Script: SOC AI → Fushion Center Case Management

Luồng hoạt động:
  1. Nhận kết quả phân tích từ SOC AI (verdict + raw_log + ai_comment).
  2. Nếu verdict == "FalsePositive" → bỏ qua, chỉ ghi log console.
  3. Nếu verdict khác (TruePositive / Suspicious / Benign) → gọi API tạo case
     trên Fushion Center theo đúng API Contract v1.0.

Cấu hình:
  Đọc từ biến môi trường (hoặc file .env) qua python-dotenv.
  Xem file .env.example để biết các biến cần thiết.

Tác giả  : SOC Automation Team
Ngày tạo : 2026-09-13
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

# ── Load .env (nếu có) ────────────────────────────────────────────────────────
load_dotenv()

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("soc_integration")

# ── Nhãn phân loại hợp lệ từ SOC AI ──────────────────────────────────────────
VALID_VERDICTS = {"TruePositive", "FalsePositive", "Benign", "Suspicious"}

# Mapping nhãn AI → severity Fushion Center
# 1=Low | 2=Medium | 3=High | 4=Critical
SEVERITY_MAP: dict[str, int] = {
    "TruePositive": 4,   # Critical — cần xử lý ngay
    "Suspicious":   3,   # High     — cần điều tra
    "Benign":       1,   # Low      — theo dõi / ghi nhận
}

# ── Dataclass: kết quả phân tích từ SOC AI ────────────────────────────────────
@dataclass
class AIAnalysisResult:
    """Biểu diễn một kết quả phân tích từ SOC AI."""

    verdict: str                           # TruePositive | FalsePositive | Benign | Suspicious
    raw_log: str                           # Log gốc đầu vào
    ai_comment: str = ""                   # Nhận xét / giải thích của AI
    source_ip: Optional[str] = None       # (tùy chọn) IP nguồn để làm phong phú title
    extra_tags: list[str] = field(default_factory=list)  # Tags bổ sung từ AI


# ── Hàm 1: Kiểm tra verdict từ SOC AI ────────────────────────────────────────
def check_ai_verdict(result: AIAnalysisResult) -> bool:
    """
    Kiểm tra nhãn AI và quyết định có cần tạo case không.

    Args:
        result: Kết quả phân tích từ SOC AI.

    Returns:
        True  → cần tạo case (TruePositive / Suspicious / Benign).
        False → bỏ qua      (FalsePositive).

    Raises:
        ValueError: Nếu verdict không thuộc tập hợp hợp lệ.
    """
    if result.verdict not in VALID_VERDICTS:
        raise ValueError(
            f"Verdict không hợp lệ: '{result.verdict}'. "
            f"Chấp nhận: {VALID_VERDICTS}"
        )

    if result.verdict == "FalsePositive":
        logger.info(
            "⏭️  [SKIPPED] Verdict = FalsePositive — bỏ qua, không tạo case. "
            "Log preview: %.120s...",
            result.raw_log,
        )
        return False

    logger.info(
        "✅ [PROCEED] Verdict = %s — tiến hành tạo case trên Fushion Center.",
        result.verdict,
    )
    return True


# ── Hàm 2: Tạo case trên Fushion Center ──────────────────────────────────────
def create_fushion_case(
    result: AIAnalysisResult,
    *,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    tenant: Optional[str] = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Gọi POST /api/v1/cases để tạo case trên Fushion Center.

    Tham số base_url, api_key, tenant mặc định đọc từ biến môi trường:
        FUSHION_API_URL   → URL backend (vd: http://localhost:3001)
        FUSHION_API_KEY   → API Key từ Admin → API Keys
        TENANT_NAME       → Tên Organization (case-sensitive)

    Args:
        result    : Kết quả AI đã qua check_ai_verdict() (verdict != FalsePositive).
        base_url  : (override) Base URL backend.
        api_key   : (override) API Key xác thực.
        tenant    : (override) Tên tenant/org.
        timeout   : Timeout HTTP request (giây).

    Returns:
        dict chứa thông tin case vừa tạo (id, number, title, ...).

    Raises:
        EnvironmentError : Thiếu biến môi trường bắt buộc.
        httpx.HTTPStatusError : Lỗi HTTP từ Fushion Center API.
        httpx.RequestError   : Lỗi kết nối mạng / timeout.
    """
    # ── Đọc config từ env (nếu không override) ──
    _base_url = (base_url or os.getenv("FUSHION_API_URL", "")).rstrip("/")
    _api_key  = api_key  or os.getenv("FUSHION_API_KEY",  "")
    _tenant   = tenant   or os.getenv("TENANT_NAME", "Default")

    if not _base_url:
        raise EnvironmentError(
            "Thiếu FUSHION_API_URL. Thiết lập trong .env hoặc biến môi trường."
        )
    if not _api_key:
        raise EnvironmentError(
            "Thiếu FUSHION_API_KEY. Thiết lập trong .env hoặc biến môi trường."
        )

    # ── Xây dựng title tự động chứa nhãn AI ──
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ip_suffix = f" — {result.source_ip}" if result.source_ip else ""
    title = f"[AI-Triage - {result.verdict}] Phát hiện bất thường{ip_suffix}"

    # ── Xây dựng description: raw log + nhận xét AI ──
    description_parts = [
        f"**AI Verdict:** {result.verdict}",
        f"**Timestamp:** {timestamp}",
        "",
        "---",
        "**Raw Log:**",
        "```",
        result.raw_log.strip(),
        "```",
    ]
    if result.ai_comment:
        description_parts += [
            "",
            "**AI Comment / Nhận xét AI:**",
            result.ai_comment.strip(),
        ]
    description = "\n".join(description_parts)

    # ── Tags: nhãn AI + tags bổ sung từ AI ──
    tags = [result.verdict, "ai-auto-triage"] + result.extra_tags

    # ── Severity theo mapping ──
    severity = SEVERITY_MAP.get(result.verdict, 2)  # fallback = Medium

    # ── Đánh dấu flag cho TruePositive ──
    flag = result.verdict == "TruePositive"

    # ── Payload JSON ──
    payload: dict[str, Any] = {
        "title":       title,
        "tenant":      _tenant,
        "description": description,
        "severity":    severity,
        "tlp":         2,   # Amber (mặc định cho tự động hóa)
        "pap":         2,
        "tags":        tags,
        "flag":        flag,
    }

    endpoint = f"{_base_url}/api/v1/cases"
    headers = {
        "X-API-Key":    _api_key,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }

    logger.info("📤 Gửi request tạo case → %s", endpoint)
    logger.debug("   Payload: %s", payload)

    # ── Gọi API ──
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)

        # ── Xử lý lỗi HTTP chi tiết theo API Contract ──
        if resp.status_code == 201:
            case_data = resp.json()
            logger.info(
                "🎉 Case tạo thành công! ID: %s | Số: #%s | Title: %s",
                case_data.get("id"),
                case_data.get("number"),
                case_data.get("title"),
            )
            return case_data

        # Đọc body lỗi (nếu có JSON)
        try:
            err_body = resp.json()
            err_msg = err_body.get("message") or err_body.get("error") or str(err_body)
        except Exception:
            err_msg = resp.text or "(không có body)"

        if resp.status_code in (400, 422):
            logger.error(
                "❌ [%d] Dữ liệu không hợp lệ — Kiểm tra lại payload. "
                "Chi tiết: %s",
                resp.status_code, err_msg,
            )
        elif resp.status_code == 401:
            logger.error(
                "❌ [401] Unauthorized — API Key không hợp lệ hoặc đã hết hạn. "
                "Chi tiết: %s", err_msg,
            )
        elif resp.status_code == 403:
            logger.error(
                "❌ [403] Forbidden — User gắn với API Key không có permission "
                "'manageCase'. Chi tiết: %s", err_msg,
            )
        elif resp.status_code == 404:
            logger.error(
                "❌ [404] Not Found — Tenant '%s' không tồn tại trong hệ thống. "
                "Hãy tạo Organization trước trong Admin. Chi tiết: %s",
                _tenant, err_msg,
            )
        elif resp.status_code == 500:
            logger.error(
                "❌ [500] Internal Server Error — Lỗi server/database. "
                "Liên hệ admin. Chi tiết: %s", err_msg,
            )
        else:
            logger.error(
                "❌ [%d] Lỗi không xác định. Chi tiết: %s",
                resp.status_code, err_msg,
            )

        resp.raise_for_status()   # Ném exception để caller biết

    except httpx.TimeoutException:
        logger.error(
            "⏰ Timeout — Không nhận được phản hồi từ Fushion Center trong %.1fs.",
            timeout,
        )
        raise
    except httpx.ConnectError as exc:
        logger.error(
            "🔌 Lỗi kết nối — Không thể kết nối tới %s. "
            "Kiểm tra FUSHION_API_URL và network. Lỗi: %s",
            endpoint, exc,
        )
        raise
    except httpx.RequestError as exc:
        logger.error("🌐 Lỗi HTTP request: %s", exc)
        raise

    # Không bao giờ chạy tới đây nhưng giúp type-checker hài lòng
    return {}


# ── Hàm tổng hợp: xử lý một kết quả AI end-to-end ───────────────────────────
def process_ai_result(
    result: AIAnalysisResult,
    **kwargs: Any,
) -> Optional[dict[str, Any]]:
    """
    Hàm điều phối chính: kiểm tra verdict rồi tạo case nếu cần.

    Args:
        result : Kết quả phân tích từ SOC AI.
        **kwargs: Tham số truyền thẳng vào create_fushion_case()
                  (base_url, api_key, tenant, timeout).

    Returns:
        dict case nếu tạo thành công, None nếu bỏ qua.
    """
    logger.info("=" * 60)
    logger.info("🔍 Xử lý AI result | Verdict: %s", result.verdict)

    should_create = check_ai_verdict(result)
    if not should_create:
        return None

    return create_fushion_case(result, **kwargs)


# ── Demo / Simulation ─────────────────────────────────────────────────────────
def _run_simulation() -> None:
    """
    Mô phỏng luồng thực tế:
      - Log 1: FalsePositive → script bỏ qua.
      - Log 2: TruePositive  → script gọi API tạo case.

    Chạy: python integration.py
    Đảm bảo file .env đã được cấu hình (xem .env.example).
    """
    logger.info("=" * 60)
    logger.info("🚀 BẮT ĐẦU MÔ PHỎNG LUỒNG SOC AI → FUSHION CENTER")
    logger.info("=" * 60)

    # ── Log 1: FalsePositive — script phải BỎ QUA ────────────────────────────
    fp_result = AIAnalysisResult(
        verdict="FalsePositive",
        raw_log=(
            "Sep 12 08:14:32 dc-01 auditd: "
            "type=USER_LOGIN msg=audit(1726135072.041:512): "
            "pid=2341 uid=0 auid=1000 ses=42 "
            "msg='op=login id=jdoe exe=/usr/sbin/sshd hostname=192.168.10.5 "
            "addr=192.168.10.5 terminal=ssh res=success'"
        ),
        ai_comment=(
            "Đây là phiên đăng nhập SSH hợp lệ của user 'jdoe' từ "
            "địa chỉ IP nội bộ đã biết (192.168.10.5). Không có dấu hiệu "
            "bất thường. Phân loại: FalsePositive."
        ),
        source_ip="192.168.10.5",
        extra_tags=["ssh", "login"],
    )

    logger.info("\n📌 [LOG 1] — Kiểm tra FalsePositive")
    process_ai_result(fp_result)

    # ── Log 2: TruePositive — script phải TẠO CASE ───────────────────────────
    tp_result = AIAnalysisResult(
        verdict="TruePositive",
        raw_log=(
            "Sep 12 14:33:12 wks-042 sysmon[3891]: "
            "EventID=1 ProcessCreate: "
            "Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
            "CommandLine='powershell.exe -nop -w hidden -enc "
            "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA' "
            "ParentImage=C:\\Windows\\explorer.exe "
            "ParentPID=4892 PID=7561 "
            "User=CORP\\jsmith "
            "Hashes=SHA256=A3B9C1D2E4F5..."
            "NetworkConnections: 185.220.101.42:443"
        ),
        ai_comment=(
            "Phát hiện PowerShell khởi chạy với tham số '-nop -w hidden -enc' — "
            "đây là dấu hiệu điển hình của kỹ thuật obfuscation/LOLBAS. "
            "Base64 payload giải mã ra lệnh tải xuống shellcode từ "
            "185.220.101.42 (Cobalt Strike C2 đã biết). "
            "Kết hợp với kết nối ngoại mạng cổng 443 từ process không phải "
            "trình duyệt → Đánh giá: TruePositive với độ tin cậy cao."
        ),
        source_ip="185.220.101.42",
        extra_tags=["cobalt-strike", "c2", "powershell", "lolbas", "apt"],
    )

    logger.info("\n📌 [LOG 2] — Kiểm tra TruePositive")
    process_ai_result(tp_result)

    logger.info("\n" + "=" * 60)
    logger.info("🏁 KẾT THÚC MÔ PHỎNG")
    logger.info("=" * 60)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    _run_simulation()
