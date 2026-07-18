"""Ollama 本地模型 Provider"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from src.llm.base import LLMProvider, retry_with_backoff
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.llm.ollama")


class OllamaProvider(LLMProvider):
    """Ollama本地模型实现"""

    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = "qwen2.5:32b", temperature: float = 0.3,
                 max_tokens: int = 4096, context_window: int = 32000):
        super().__init__(model, temperature, max_tokens, context_window)
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=300.0)
        logger.info(f"Ollama Provider 已初始化: model={model}, url={base_url}")

    def close(self):
        """关闭 httpx 连接池，释放资源"""
        if self.client:
            self.client.close()

    @retry_with_backoff(max_retries=3, base_delay=2.0, max_delay=30.0)
    def chat(self, messages: List[Dict[str, str]],
             temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        t0 = time.time()
        try:
            response = self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": temperature if temperature is not None else self.temperature,
                        "num_predict": max_tokens if max_tokens is not None else self.max_tokens,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()
            content = data.get("message", {}).get("content", "")
            duration = time.time() - t0

            # Ollama 返回的 token 统计
            prompt_eval = data.get("prompt_eval_count", 0)
            eval_count = data.get("eval_count", 0)
            if prompt_eval or eval_count:
                self.usage_stats.record(prompt_eval, eval_count, duration)
            else:
                prompt_text = " ".join(m.get("content", "") for m in messages)
                self.usage_stats.record(
                    self.get_token_count(prompt_text),
                    self.get_token_count(content),
                    duration,
                )

            logger.debug(f"Ollama响应 ({duration:.1f}s): {content[:100]}...")
            return content
        except Exception as e:
            logger.error(f"Ollama API调用失败: {e}")
            raise

    def get_token_count(self, text: str) -> int:
        cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        en_chars = len(text) - cn_chars
        return int(cn_chars / 1.5 + en_chars / 4)
