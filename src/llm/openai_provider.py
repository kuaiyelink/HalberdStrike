"""OpenAI API Provider"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from openai import OpenAI

from src.llm.base import LLMProvider, retry_with_backoff
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.llm.openai")


class OpenAIProvider(LLMProvider):
    """OpenAI兼容API实现"""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o", temperature: float = 0.3,
                 max_tokens: int = 4096, context_window: int = 128000):
        super().__init__(model, temperature, max_tokens, context_window)
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        logger.info(f"OpenAI Provider 已初始化: model={model}, base_url={base_url}")

    @retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=30.0)
    def chat(self, messages: List[Dict[str, str]],
             temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> str:
        t0 = time.time()
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature if temperature is not None else self.temperature,
                max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
            )
            content = response.choices[0].message.content or ""
            duration = time.time() - t0

            # 记录 token 用量
            usage = getattr(response, 'usage', None)
            if usage:
                self.usage_stats.record(
                    prompt_tokens=usage.prompt_tokens or 0,
                    completion_tokens=usage.completion_tokens or 0,
                    duration=duration,
                )
            else:
                # API 不返回 usage 时用估算值
                prompt_text = " ".join(m.get("content", "") for m in messages)
                self.usage_stats.record(
                    prompt_tokens=self.get_token_count(prompt_text),
                    completion_tokens=self.get_token_count(content),
                    duration=duration,
                )

            logger.debug(f"LLM响应 ({duration:.1f}s): {content[:100]}...")
            return content
        except Exception as e:
            logger.error(f"OpenAI API调用失败: {e}")
            raise

    def get_token_count(self, text: str) -> int:
        """估算token数（中文约1.5字/token，英文约4字符/token）"""
        cn_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
        en_chars = len(text) - cn_chars
        return int(cn_chars / 1.5 + en_chars / 4)
