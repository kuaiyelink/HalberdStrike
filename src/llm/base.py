"""LLM Provider 抽象基类"""

from __future__ import annotations

import json
import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger("halberdstrike.llm")


@dataclass
class TokenUsageStats:
    """Token 用量统计"""
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    total_retries: int = 0
    total_cost_seconds: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, prompt_tokens: int, completion_tokens: int, duration: float):
        with self._lock:
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens
            self.total_requests += 1
            self.total_cost_seconds += duration

    def record_failure(self):
        with self._lock:
            self.failed_requests += 1

    def record_retry(self):
        with self._lock:
            self.total_retries += 1

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "prompt_tokens": self.total_prompt_tokens,
                "completion_tokens": self.total_completion_tokens,
                "total_tokens": self.total_tokens,
                "requests": self.total_requests,
                "failed": self.failed_requests,
                "retries": self.total_retries,
                "avg_latency": round(self.total_cost_seconds / max(self.total_requests, 1), 2),
            }


def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0,
                       max_delay: float = 30.0, backoff_factor: float = 2.0):
    """指数退避重试装饰器，处理 429/5xx 等瞬态错误"""
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(self, *args, **kwargs)
                except Exception as e:
                    last_exc = e
                    err_str = str(e).lower()
                    is_retryable = any(k in err_str for k in [
                        "429", "rate_limit", "rate limit",
                        "500", "502", "503", "504",
                        "timeout", "timed out", "connection",
                        "overloaded", "server_error",
                    ])
                    if not is_retryable or attempt >= max_retries:
                        if hasattr(self, 'usage_stats'):
                            self.usage_stats.record_failure()
                        raise
                    delay = min(base_delay * (backoff_factor ** attempt), max_delay)
                    if hasattr(self, 'usage_stats'):
                        self.usage_stats.record_retry()
                    logger.warning(
                        f"LLM调用失败 (尝试 {attempt+1}/{max_retries+1}), "
                        f"{delay:.1f}s后重试: {str(e)[:120]}"
                    )
                    time.sleep(delay)
            raise last_exc
        return wrapper
    return decorator


class LLMProvider(ABC):
    """LLM服务提供者抽象基类"""

    def __init__(self, model: str, temperature: float = 0.3,
                 max_tokens: int = 4096, context_window: int = 128000):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.context_window = context_window
        self.usage_stats = TokenUsageStats()

    @abstractmethod
    def chat(self, messages: List[Dict[str, str]],
             temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        """发送聊天请求，返回文本响应"""
        ...

    def chat_json(self, messages: List[Dict[str, str]],
                  temperature: Optional[float] = None,
                  max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """发送聊天请求，强制返回JSON"""
        json_instruction = {
            "role": "system",
            "content": "你必须严格以标准JSON格式回复。要求：1) 使用双引号而非单引号；2) 布尔值用 true/false 而非 True/False；3) 空值用 null 而非 None；4) 不要包含markdown代码块标记、注释或任何非JSON文本。只输出纯JSON对象。"
        }
        augmented = messages.copy()
        augmented.insert(1 if len(augmented) > 1 else 0, json_instruction)

        response = self.chat(augmented, temperature=temperature, max_tokens=max_tokens)
        return self._parse_json_response(response)

    @staticmethod
    def _parse_json_response(response: str) -> Dict[str, Any]:
        """从 LLM 原始响应中提取 JSON，支持多种包装格式"""
        import ast
        import re
        response = response.strip()

        # 去除 markdown 代码块
        if response.startswith("```"):
            response = re.sub(r"^```(?:json)?\s*", "", response)
            response = re.sub(r"\s*```$", "", response)

        # 直接解析
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # 提取最外层 { ... }
        brace_depth = 0
        start = -1
        candidate = ""
        for i, c in enumerate(response):
            if c == '{':
                if brace_depth == 0:
                    start = i
                brace_depth += 1
            elif c == '}':
                brace_depth -= 1
                if brace_depth == 0 and start >= 0:
                    candidate = response[start:i+1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass
                    break

        # 修复常见的非标准 JSON：单引号、Python 布尔/None
        if candidate or ('{' in response and '}' in response):
            text = candidate or response
            try:
                # 将 Python 字面量修复为 JSON 兼容格式
                import re as _re
                fixed = _re.sub(r'\bTrue\b', 'true', text)
                fixed = _re.sub(r'\bFalse\b', 'false', fixed)
                fixed = _re.sub(r'\bNone\b', 'null', fixed)
                result = json.loads(fixed)
                return result
            except json.JSONDecodeError:
                pass
            # ast.literal_eval 兜底：解析 Python dict 字面量（单引号等）
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, SyntaxError):
                pass

        logger.warning(f"LLM返回非JSON内容: {response[:200]}...")
        return {"raw_response": response, "parse_error": True}

    @abstractmethod
    def get_token_count(self, text: str) -> int:
        """估算文本的token数量"""
        ...
