"""命令执行进度追踪与实时展示"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

from src.utils.logger import get_logger

logger = get_logger("halberdstrike.tools.progress")


# ─────────────────────────── 数据模型 ───────────────────────────

@dataclass
class ProcessInfo:
    """单个进程的运行状态"""
    pid: int
    command: str
    timeout: float
    start_time: float = field(default_factory=time.time)
    output_bytes: int = 0
    progress: float = 0.0          # 0.0 ~ 1.0
    eta_seconds: float = 0.0
    speed_bps: float = 0.0         # bytes per second
    status: str = "running"        # running / completed / failed / timeout
    bar_text: str = ""

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def progress_pct(self) -> int:
        return min(int(self.progress * 100), 100)


# ─────────────────────────── 进度条渲染器 ───────────────────────────

class ProgressRenderer:
    """将进度数据渲染为带颜色的文本进度条"""

    BAR_WIDTH = 30
    FILL_CHAR = "█"
    EMPTY_CHAR = "░"

    # ANSI 颜色
    COLOR_GREEN = "\033[92m"
    COLOR_YELLOW = "\033[93m"
    COLOR_RED = "\033[91m"
    COLOR_CYAN = "\033[96m"
    COLOR_RESET = "\033[0m"
    COLOR_BOLD = "\033[1m"

    @classmethod
    def render(cls, info: ProcessInfo) -> str:
        """渲染一条进度条文本"""
        pct = info.progress_pct
        filled = int(cls.BAR_WIDTH * info.progress)
        bar = cls.FILL_CHAR * filled + cls.EMPTY_CHAR * (cls.BAR_WIDTH - filled)

        # 根据进度选颜色
        if pct >= 80:
            color = cls.COLOR_GREEN
        elif pct >= 40:
            color = cls.COLOR_YELLOW
        else:
            color = cls.COLOR_CYAN

        # ETA
        if info.eta_seconds > 0:
            eta_m, eta_s = divmod(int(info.eta_seconds), 60)
            eta_str = f"{eta_m}m{eta_s:02d}s" if eta_m else f"{eta_s}s"
        else:
            eta_str = "--"

        # 速度
        if info.speed_bps > 1024:
            speed_str = f"{info.speed_bps / 1024:.1f} KB/s"
        elif info.speed_bps > 0:
            speed_str = f"{info.speed_bps:.0f} B/s"
        else:
            speed_str = "--"

        # 已用时间
        elapsed_m, elapsed_s = divmod(int(info.elapsed), 60)
        elapsed_str = f"{elapsed_m}m{elapsed_s:02d}s" if elapsed_m else f"{elapsed_s}s"

        # 命令名（取前30字符）
        cmd_short = info.command[:30] + ("…" if len(info.command) > 30 else "")

        bar_text = (
            f"{color}{cls.COLOR_BOLD}{cmd_short}{cls.COLOR_RESET} "
            f"|{color}{bar}{cls.COLOR_RESET}| "
            f"{pct:3d}% "
            f"⏱ {elapsed_str} "
        )
        return bar_text

    @classmethod
    def render_completed(cls, info: ProcessInfo) -> str:
        """渲染完成状态"""
        elapsed_m, elapsed_s = divmod(int(info.elapsed), 60)
        elapsed_str = f"{elapsed_m}m{elapsed_s:02d}s" if elapsed_m else f"{elapsed_s}s"
        cmd_short = info.command[:30] + ("…" if len(info.command) > 30 else "")

        status_map = {
            "completed": (cls.COLOR_GREEN, "✓ 完成"),
            "failed": (cls.COLOR_RED, "✗ 失败"),
            "timeout": (cls.COLOR_RED, "⏰ 超时"),
        }
        color, label = status_map.get(info.status, (cls.COLOR_RESET, info.status))

        bar = cls.FILL_CHAR * cls.BAR_WIDTH
        return (
            f"{color}{cls.COLOR_BOLD}{cmd_short}{cls.COLOR_RESET} "
            f"|{color}{bar}{cls.COLOR_RESET}| "
            f"{label} "
            f"⏱ {elapsed_str}"
        )


# ─────────────────────────── 进程管理器（全局单例） ───────────────────────────

class ProcessManager:
    """全局进程状态管理器"""

    _instance: Optional["ProcessManager"] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._processes: Dict[int, ProcessInfo] = {}
                cls._instance._mgr_lock = threading.Lock()
            return cls._instance

    def register(self, pid: int, command: str, timeout: float) -> ProcessInfo:
        """注册一个新进程"""
        info = ProcessInfo(pid=pid, command=command, timeout=timeout)
        with self._mgr_lock:
            self._processes[pid] = info
        return info

    def unregister(self, pid: int):
        """注销进程"""
        with self._mgr_lock:
            self._processes.pop(pid, None)

    def get(self, pid: int) -> Optional[ProcessInfo]:
        with self._mgr_lock:
            return self._processes.get(pid)

    def get_active(self) -> List[ProcessInfo]:
        """获取所有活动进程"""
        with self._mgr_lock:
            return [p for p in self._processes.values() if p.status == "running"]

    def get_all(self) -> List[ProcessInfo]:
        """获取所有进程（含已结束）"""
        with self._mgr_lock:
            return list(self._processes.values())

    def get_dashboard(self) -> List[Dict]:
        """MCP 仪表盘接口：返回所有活动进程的状态"""
        active = self.get_active()
        return [
            {
                "pid": p.pid,
                "command": p.command,
                "progress_pct": p.progress_pct,
                "eta_seconds": round(p.eta_seconds, 1),
                "elapsed": round(p.elapsed, 1),
                "speed_bps": round(p.speed_bps, 1),
                "output_bytes": p.output_bytes,
                "status": p.status,
                "bar_text": p.bar_text,
            }
            for p in active
        ]


# ─────────────────────────── 进度追踪线程 ───────────────────────────

class ProgressTracker:
    """为单个命令执行提供进度追踪的后台线程"""

    UPDATE_INTERVAL = 0.5  # 刷新间隔（秒）

    def __init__(self, pid: int, command: str, timeout: float,
                 proc_handle=None, console_output: bool = True):
        self.pid = pid
        self.command = command
        self.timeout = timeout
        self.proc_handle = proc_handle
        self.console_output = console_output

        self.manager = ProcessManager()
        self.info = self.manager.register(pid, command, timeout)

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_output_size = 0

    def start(self):
        """启动进度追踪线程"""
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"progress-{self.pid}"
        )
        self._thread.start()

    def stop(self, status: str = "completed"):
        """停止追踪"""
        self._stop_event.set()
        self.info.status = status
        self.info.progress = 1.0 if status == "completed" else self.info.progress
        self.info.eta_seconds = 0

        # 渲染最终状态
        final_bar = ProgressRenderer.render_completed(self.info)
        self.info.bar_text = final_bar
        if self.console_output:
            self._print_bar(final_bar, newline=True)

        self.manager.unregister(self.pid)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def update_output_size(self, size: int):
        """更新已收到的输出字节数"""
        self.info.output_bytes = size

    def _run(self):
        """进度线程主循环"""
        while not self._stop_event.is_set():
            self._update_progress()

            bar_text = ProgressRenderer.render(self.info)
            self.info.bar_text = bar_text

            if self.console_output:
                self._print_bar(bar_text)

            self._stop_event.wait(self.UPDATE_INTERVAL)

    def _update_progress(self):
        """基于 已运行时间 / 超时 估算进度"""
        elapsed = self.info.elapsed
        timeout = self.timeout

        # 核心算法：使用对数曲线，前期快后期慢，永远不会到100%
        # 这样在接近超时时进度不会显得"卡住"
        if timeout > 0:
            ratio = elapsed / timeout
            # 使用 easing 函数：快速到 80%，然后慢慢逼近 95%
            if ratio < 0.8:
                progress = ratio * 0.9  # 80%时间内线性到72%
            elif ratio < 1.0:
                # 80%~100%时间: 72%~95%
                sub_ratio = (ratio - 0.8) / 0.2
                progress = 0.72 + sub_ratio * 0.23
            else:
                # 超时了还在跑
                progress = 0.95 + min((ratio - 1.0) * 0.02, 0.04)
        else:
            progress = 0.0

        self.info.progress = min(progress, 0.99)

        # ETA 估算
        if progress > 0.01:
            estimated_total = elapsed / progress
            self.info.eta_seconds = max(estimated_total - elapsed, 0)
        else:
            self.info.eta_seconds = timeout

        # 速度（基于输出字节数）
        if elapsed > 0.5:
            self.info.speed_bps = self.info.output_bytes / elapsed
        else:
            self.info.speed_bps = 0

    @staticmethod
    def _print_bar(text: str, newline: bool = False):
        """在同一行刷新进度条"""
        end = "\n" if newline else ""
        sys.stderr.write(f"\r\033[K{text}{end}")
        sys.stderr.flush()
