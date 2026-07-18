"""日志工具"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler

_loggers: dict[str, logging.Logger] = {}


def setup_logger(
    name: str = "halberdstrike",
    level: str = "INFO",
    log_file: Optional[str] = None,
    console: bool = True,
) -> logging.Logger:
    """初始化并返回日志实例（重复调用会更新配置）"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    fmt = "%(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    if console:
        console_handler = RichHandler(
            rich_tracebacks=True,
            show_path=False,
            markup=True,
        )
        console_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        logger.addHandler(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        file_handler.setFormatter(logging.Formatter(file_fmt, datefmt=datefmt))
        logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger


def get_logger(name: str = "halberdstrike") -> logging.Logger:
    """获取已有日志实例，不存在则创建默认实例

    子 logger（如 halberdstrike.core.xxx）不添加 handler，
    依赖 Python logging 层级传播到根 'halberdstrike' logger。
    """
    if name not in _loggers:
        if name == "halberdstrike":
            return setup_logger(name)
        # 确保根 logger 已初始化
        if "halberdstrike" not in _loggers:
            setup_logger("halberdstrike")
        logger = logging.getLogger(name)
        _loggers[name] = logger
        return logger
    return _loggers[name]
