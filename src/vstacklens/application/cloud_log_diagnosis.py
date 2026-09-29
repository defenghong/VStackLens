from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit


DEFAULT_CLOUD_PROVIDER = "deepseek"
DEFAULT_CLOUD_API_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_CLOUD_MODEL = "deepseek-reasoner"
MODEL_PROTOCOL = "openai_compatible"


@dataclass(slots=True)
class CloudModelConfig:
    provider: str = DEFAULT_CLOUD_PROVIDER
    api_url: str = DEFAULT_CLOUD_API_URL
    model_name: str = DEFAULT_CLOUD_MODEL
    api_key: str = ""
    timeout_seconds: int = 60

    def normalized(self) -> "CloudModelConfig":
        return CloudModelConfig(
            provider=(self.provider or DEFAULT_CLOUD_PROVIDER).strip() or DEFAULT_CLOUD_PROVIDER,
            api_url=(self.api_url or DEFAULT_CLOUD_API_URL).strip() or DEFAULT_CLOUD_API_URL,
            model_name=(self.model_name or DEFAULT_CLOUD_MODEL).strip() or DEFAULT_CLOUD_MODEL,
            api_key=(self.api_key or "").strip(),
            timeout_seconds=max(5, int(self.timeout_seconds or 60)),
        )


@dataclass(slots=True)
class CloudModelResult:
    ok: bool
    content: dict[str, Any] | None = None
    fallback_reason: str = ""
    elapsed_ms: int = 0
    response_received: bool = False


class CloudResponseError(ValueError):
    """Raised when the endpoint returned a response that is not usable chat JSON."""


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.S)


def sanitize_cloud_error(message: Any, api_key: str = "") -> str:
    text = str(message or "").strip()
    if api_key:
        text = text.replace(api_key, "***")
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+", r"\1***", text)
    text = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1***", text)
    text = re.sub(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|sessionid|session|cookie)\s*=\s*[^\s;&,]+", r"\1=***", text)
    if len(text) > 500:
        text = text[:500] + "..."
    return text or "云端辅助分析调用失败。"


def describe_cloud_failure(exc: Exception, api_key: str = "") -> str:
    raw_message = _cloud_exception_message(exc, api_key)
    lower = raw_message.lower()

    quota_terms = ("insufficient_quota", "insufficient quota", "insufficient balance", "quota", "balance", "billing", "余额", "额度")
    rate_limit_terms = ("rate_limit", "rate limit", "too many requests", "429", "限流")
    model_terms = ("model_not_found", "model not found", "model unavailable", "model is unavailable", "does not exist", "not support", "模型不存在", "模型不可用")

    if isinstance(exc, urllib.error.HTTPError):
        code = int(exc.code or 0)
        if code == 401:
            return _with_cloud_detail("认证失败（HTTP 401），请检查 API Key 是否正确、是否已启用对应模型权限。", raw_message)
        if code == 403:
            return _with_cloud_detail("权限不足（HTTP 403），请检查账号权限、模型权限或访问策略。", raw_message)
        if code == 429:
            return _with_cloud_detail("请求被限流或账号额度不足（HTTP 429），请稍后重试或检查账号余额与调用频率。", raw_message)
        if code >= 500:
            return _with_cloud_detail(f"云端服务暂时不可用（HTTP {code}），请稍后重试。", raw_message)

    if any(term in lower for term in quota_terms):
        return _with_cloud_detail("账号额度或余额不足，请检查云端模型账号余额、套餐额度或计费状态。", raw_message)
    if any(term in lower for term in rate_limit_terms):
        return _with_cloud_detail("请求被云端模型服务限流，请稍后重试或降低调用频率。", raw_message)
    if any(term in lower for term in model_terms):
        return _with_cloud_detail("模型不可用或模型名无权限，请检查模型名称、账号权限和服务商开放状态。", raw_message)
    if isinstance(exc, TimeoutError | socket.timeout):
        return "网络连接超时，请检查网络连通性、代理或云端 API 地址。"
    if isinstance(exc, urllib.error.URLError):
        reason = str(getattr(exc, "reason", "") or "")
        if "timed out" in reason.lower() or "timeout" in reason.lower():
            return _with_cloud_detail("网络连接超时，请检查网络连通性、代理或云端 API 地址。", raw_message)
        return _with_cloud_detail("无法连接云端模型服务，请检查网络连通性、代理或云端 API 地址。", raw_message)
    return raw_message or "云端辅助分析调用失败。"


def _cloud_exception_message(exc: Exception, api_key: str = "") -> str:
    if isinstance(exc, urllib.error.HTTPError):
        body = ""
        try:
            if exc.fp is not None:
                body = exc.fp.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - best-effort diagnostics only.
            body = ""
        status = f"HTTP {exc.code}: {exc.reason or exc}"
        if body:
            status = f"{status} {body}"
        return sanitize_cloud_error(status, api_key)
    return sanitize_cloud_error(str(exc), api_key)


def _with_cloud_detail(prefix: str, detail: str) -> str:
    clean_detail = sanitize_cloud_error(detail)
    if not clean_detail or clean_detail == prefix:
        return prefix
    if len(clean_detail) > 260:
        clean_detail = clean_detail[:260] + "..."
    return f"{prefix} 接口返回：{clean_detail}"


class CloudModelClient:
    """OpenAI-compatible chat/completions client for optional cloud-assisted log diagnosis."""

    SYSTEM_PROMPT = "你是 VMware support bundle 日志诊断助手。只能基于给定证据判断，不要编造日志中不存在的事实。输出中文 JSON。"

    def __init__(self, config: CloudModelConfig) -> None:
        self.config = config.normalized()

    def diagnose(self, user_prompt: str) -> CloudModelResult:
        return self._chat(user_prompt, require_schema=True)

    def complete_json(self, user_prompt: str) -> CloudModelResult:
        return self._chat(user_prompt, require_schema=False)

    def test_connection(self) -> CloudModelResult:
        return self._chat('请返回 JSON：{"ok":true,"message":"连接成功"}', require_schema=False)

    def list_models(self) -> CloudModelResult:
        start = time.monotonic()
        try:
            url = self._models_api_url()
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:  # noqa: S310
                response_text = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(response_text)
            if not isinstance(parsed, dict):
                raise CloudResponseError("模型列表接口返回不是 JSON object。")
            data = parsed.get("data")
            if not isinstance(data, list):
                raise CloudResponseError("模型列表接口返回缺少 data。")
            models = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                model_id = str(item.get("id") or "").strip()
                if model_id:
                    models.append(model_id)
            models = list(dict.fromkeys(models))
            if not models:
                raise CloudResponseError("模型列表接口未返回可用模型。")
            return CloudModelResult(True, content={"models": models}, elapsed_ms=_elapsed_ms(start), response_received=True)
        except Exception as exc:  # noqa: BLE001
            return self._failure(exc, start)

    def _chat(self, user_prompt: str, require_schema: bool) -> CloudModelResult:
        start = time.monotonic()
        try:
            raw = self._request(user_prompt, include_response_format=True)
        except CloudResponseError as exc:
            return self._failure(exc, start, response_received=True)
        except urllib.error.HTTPError as exc:
            if exc.code in {400, 422}:
                try:
                    raw = self._request(user_prompt, include_response_format=False)
                except CloudResponseError as retry_exc:
                    return self._failure(retry_exc, start, response_received=True)
                except Exception as retry_exc:  # noqa: BLE001 - sanitized below.
                    return self._failure(retry_exc, start)
            else:
                return self._failure(exc, start)
        except Exception as exc:  # noqa: BLE001 - cloud fallback must never leak implementation details.
            return self._failure(exc, start)

        try:
            content = self._extract_message_content(raw)
            data = _parse_json_object(content)
            if require_schema:
                validation_error = _validate_diagnosis_schema(data)
                if validation_error:
                    return CloudModelResult(False, fallback_reason=validation_error, elapsed_ms=_elapsed_ms(start), response_received=True)
            return CloudModelResult(True, content=data, elapsed_ms=_elapsed_ms(start), response_received=True)
        except Exception as exc:  # noqa: BLE001 - keep fallback sanitized.
            return self._failure(exc, start, response_received=True)

    def _request(self, user_prompt: str, *, include_response_format: bool) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "stream": False,
        }
        if include_response_format:
            body["response_format"] = {"type": "json_object"}

        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.config.api_url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:  # noqa: S310 - user supplied endpoint.
            response_text = response.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise CloudResponseError("云端接口返回不是有效 JSON。") from exc
        if not isinstance(parsed, dict):
            raise CloudResponseError("云端接口返回不是 JSON object。")
        return parsed

    def _models_api_url(self) -> str:
        api_url = self.config.api_url.strip()
        if api_url.endswith("/v1/chat/completions"):
            return api_url[: -len("/chat/completions")] + "/models"
        if api_url.endswith("/chat/completions"):
            return api_url[: -len("/chat/completions")] + "/models"
        if api_url.endswith("/v1/completions"):
            return api_url[: -len("/completions")] + "/models"
        parsed = urlsplit(api_url)
        if parsed.path.endswith("/v1/models"):
            return api_url
        if "/v1/" in parsed.path:
            prefix = parsed.path.split("/v1/", 1)[0]
            return urlunsplit((parsed.scheme, parsed.netloc, f"{prefix}/v1/models", parsed.query, parsed.fragment))
        return urlunsplit((parsed.scheme, parsed.netloc, "/v1/models", parsed.query, parsed.fragment))

    def _extract_message_content(self, raw: dict[str, Any]) -> str:
        choices = raw.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("云端接口响应缺少 choices。")
        first = choices[0]
        if not isinstance(first, dict):
            raise ValueError("云端接口 choices 格式不正确。")
        message = first.get("message")
        if not isinstance(message, dict):
            raise ValueError("云端接口响应缺少 message。")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("云端接口响应内容为空。")
        return content

    def _failure(self, exc: Exception, start: float, *, response_received: bool = False) -> CloudModelResult:
        reason = describe_cloud_failure(exc, self.config.api_key)
        return CloudModelResult(False, fallback_reason=reason, elapsed_ms=_elapsed_ms(start), response_received=response_received)


def _elapsed_ms(start: float) -> int:
    return max(0, int((time.monotonic() - start) * 1000))


def _parse_json_object(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = _JSON_BLOCK_RE.search(text)
        if not match:
            raise ValueError("云端接口响应不是有效 JSON。") from None
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        raise ValueError("云端接口响应 JSON 不是 object。")
    return data


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _validate_diagnosis_schema(data: dict[str, Any]) -> str:
    judgement = str(data.get("current_judgement") or "").strip()
    if len(judgement) < 30:
        return "云端辅助分析返回的当前判断过短，已回退为离线规则排查。"
    if not _string_list(data.get("evidence_reasoning")):
        return "云端辅助分析缺少证据推理，已回退为离线规则排查。"
    if not _string_list(data.get("missing_materials")):
        return "云端辅助分析缺少补充材料，已回退为离线规则排查。"
    if not _string_list(data.get("recommended_actions")):
        return "云端辅助分析缺少处理建议，已回退为离线规则排查。"
    confidence = str(data.get("confidence") or "").strip()
    if confidence not in {"低", "中", "高"}:
        return "云端辅助分析置信度字段无效，已回退为离线规则排查。"
    return ""
