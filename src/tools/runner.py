"""命令执行沙箱"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from src.utils.logger import get_logger
from src.tools.progress import ProgressTracker

logger = get_logger("halberdstrike.tools.runner")


@dataclass
class ExecutionResult:
    """命令执行结果"""
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """合并stdout和stderr"""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(f"[STDERR] {self.stderr.strip()}")
        return "\n".join(parts) if parts else "(无输出)"

    def truncated_output(self, max_chars: int = 4000) -> str:
        """获取截断后的输出"""
        out = self.output
        if len(out) <= max_chars:
            return out
        half = max_chars // 2
        return (
            out[:half]
            + f"\n\n... [输出被截断, 总长度 {len(out)} 字符] ...\n\n"
            + out[-half:]
        )


class CommandRunner:
    """安全的命令执行器"""

    def __init__(self, default_timeout: int = 300, max_output_size: int = 1048576,
                 show_progress: bool = True):
        self.default_timeout = default_timeout
        self.max_output_size = max_output_size
        self.show_progress = show_progress
        self._is_windows = os.name == 'nt'

    def _build_subprocess_env(self) -> dict:
        """构建子进程环境变量，并优先注入发布包内的工具目录。"""
        env = os.environ.copy()
        base_dir = os.getcwd()
        platform_dir = "windows" if self._is_windows else "linux"
        candidate_dirs = [
            os.path.join(base_dir, "tools", platform_dir),
            os.path.join(base_dir, "release", platform_dir, "tools", platform_dir),
        ]
        existing = [p for p in candidate_dirs if os.path.isdir(p)]
        if existing:
            env["PATH"] = os.pathsep.join(existing + [env.get("PATH", "")])
        return env

    def _sanitize_command(self, command: str) -> str:
        """平台适配：修正命令使其在当前OS上可执行"""
        if not self._is_windows:
            return command

        import re
        # 1) 单引号包裹的参数 → 双引号（简单场景，不处理嵌套引号）
        #    仅替换作为参数定界符的单引号，不替换内嵌在字符串中的
        command = re.sub(
            r"(?<=\s)'([^']*)'(?=\s|$)",
            r'"\1"',
            ' ' + command  # 前加空格让首参也匹配 (?<=\s)
        ).lstrip()
        # 也处理命令开头的单引号参数
        if command.startswith("'"):
            command = re.sub(r"^'([^']*)'(?=\s|$)", r'"\1"', command)

        # 2) python3 → python（Windows 下通常只有 python）
        command = re.sub(r'\bpython3\b', 'python', command)

        # 3) /dev/null → NUL
        command = command.replace('/dev/null', 'NUL')

        # 4) head -N → 移除（Windows 没有 head）
        command = re.sub(r'\|\s*head\s+-\d+', '', command)

        # 5) 2>&1 在 Windows cmd 下是支持的，无需改动

        return command.strip()

    def execute(self, command: str, timeout: Optional[int] = None,
                cwd: Optional[str] = None) -> ExecutionResult:
        """执行命令并捕获输出

        Args:
            command: 要执行的shell命令
            timeout: 超时时间（秒）
            cwd: 工作目录
        """
        timeout = timeout or self.default_timeout
        command = self._sanitize_command(command)
        logger.info(f"执行命令: {command}")
        start_time = time.time()
        timed_out = False

        tracker = None
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=self._build_subprocess_env(),
                preexec_fn=os.setsid if os.name != 'nt' else None,
            )

            # 启动进度追踪
            if self.show_progress:
                tracker = ProgressTracker(
                    pid=proc.pid,
                    command=command,
                    timeout=timeout,
                    proc_handle=proc,
                    console_output=True,
                )
                tracker.start()

            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning(f"命令超时 ({timeout}s): {command}")
                timed_out = True
                if os.name != 'nt':
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    time.sleep(2)
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate(timeout=5)

            duration = time.time() - start_time

            stdout = self._decode_output(stdout_bytes)
            stderr = self._decode_output(stderr_bytes)

            # 更新进度追踪的输出字节数
            if tracker:
                tracker.update_output_size(len(stdout_bytes) + len(stderr_bytes))

            if len(stdout) > self.max_output_size:
                stdout = stdout[:self.max_output_size] + "\n[输出被截断]"
            if len(stderr) > self.max_output_size:
                stderr = stderr[:self.max_output_size] + "\n[输出被截断]"

            result = ExecutionResult(
                command=command,
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=stdout,
                stderr=stderr,
                duration=duration,
                timed_out=timed_out,
            )

            # 停止进度追踪
            if tracker:
                status = "timeout" if timed_out else ("completed" if result.success else "failed")
                tracker.stop(status)

            logger.info(
                f"命令完成: returncode={result.returncode}, "
                f"duration={duration:.1f}s, timed_out={timed_out}"
            )
            return result

        except Exception as e:
            duration = time.time() - start_time
            if tracker:
                tracker.stop("failed")
            logger.error(f"命令执行异常: {e}")
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout="",
                stderr=str(e),
                duration=duration,
                timed_out=False,
            )

    def _decode_output(self, data: bytes) -> str:
        """尝试多种编码解码输出"""
        for encoding in ["utf-8", "latin-1", "gbk"]:
            try:
                return data.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("utf-8", errors="replace")
