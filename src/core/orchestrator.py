"""协调控制器 - 主循环/状态机/事件调度"""

from __future__ import annotations

import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.core.generation import GenerationModule
from src.core.parsing import ParsingModule
from src.core.reasoning import ReasoningModule
from src.llm.base import LLMProvider
from src.llm.context_manager import ContextManager
from src.llm.ollama_provider import OllamaProvider
from src.llm.openai_provider import OpenAIProvider
from src.models.action_log import ActionLog, ActionType, ApprovalSource, ModuleType, RiskLevel
from src.models.finding import Finding, FindingType, Severity
from src.models.project import Project
from src.ptt.node import NodeStatus
from src.ptt.serializer import PTTSerializer
from src.storage.database import Database
from src.storage.file_store import FileStore
from src.tools.generic_adapter import get_adapter
from src.tools.runner import CommandRunner, ExecutionResult
from src.utils.logger import get_logger, setup_logger
from src.utils.validator import CommandValidator, ScopeValidator

logger = get_logger("halberdstrike.orchestrator")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


class Orchestrator:
    """协调控制器 - 驱动整个渗透测试流程

    核心循环:
    1. 推理模块选择下一个任务
    2. 生成模块生成命令
    3. 校验+审批命令
    4. 执行命令
    5. 解析模块处理输出
    6. 推理模块更新PTT
    7. 回到步骤1
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self._init_components()
        self.project: Optional[Project] = None
        self.is_running = False
        self.is_paused = False
        self.consecutive_failures = 0
        self._approval_callback = None
        self._parallel_workers = self.config.get("execution", {}).get("parallel_workers", 1)
        self._exec_lock = threading.Lock()
        self._pending_guidance: List[str] = []
        # Web 仪表盘用：主循环当前阶段（LLM 调用期间无子进程时也能显示“在跑”）
        self._activity_phase: str = "idle"
        self._activity_detail: str = ""
        self._run_iteration_current: int = 0
        self._run_iteration_max: int = 0
        self._current_task_name: str = ""

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        path = self._resolve_project_path(config_path) if config_path else CONFIG_DIR / "config.yaml"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            api_key_ref = config.get("llm", {}).get("api_key", "")
            if api_key_ref.startswith("${") and api_key_ref.endswith("}"):
                env_var = api_key_ref[2:-1]
                config["llm"]["api_key"] = os.environ.get(env_var, "")
            return self._normalize_config_paths(config)
        logger.warning(f"配置文件不存在: {path}，使用默认配置")
        return self._normalize_config_paths({
            "llm": {"provider": "openai", "api_key": "", "model": "gpt-4o",
                     "temperature": 0.3, "max_tokens": 4096, "context_window": 128000},
            "execution": {"default_timeout": 300, "max_retries": 3,
                          "auto_approve_risk_levels": ["low"],
                          "max_consecutive_failures": 3},
            "security": {"blocked_commands": [], "network_scope_enforcement": True},
            "storage": {"database_path": "./data/halberdstrike.db",
                        "projects_dir": "./data/projects",
                        "reports_dir": "./data/reports"},
            "logging": {"level": "INFO", "file": "./data/logs/halberdstrike.log"},
        })

    @staticmethod
    def _resolve_project_path(path_value: Optional[str]) -> Optional[Path]:
        if not path_value:
            return None
        path = Path(path_value)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path.resolve()

    def _normalize_config_paths(self, config: Dict[str, Any]) -> Dict[str, Any]:
        storage_cfg = config.setdefault("storage", {})
        # 补全缺省/空值，并一律相对项目根解析，避免依赖启动时的 CWD 导致 ./data 指向错误目录
        storage_defaults = {
            "database_path": "./data/halberdstrike.db",
            "projects_dir": "./data/projects",
            "reports_dir": "./data/reports",
            "logs_dir": "./data/logs",
        }
        for key, default in storage_defaults.items():
            val = storage_cfg.get(key)
            if val is None or (isinstance(val, str) and not val.strip()):
                storage_cfg[key] = default

        for key in ("database_path", "projects_dir", "reports_dir", "logs_dir"):
            value = storage_cfg.get(key)
            resolved = self._resolve_project_path(value)
            if resolved:
                storage_cfg[key] = str(resolved)

        logging_cfg = config.setdefault("logging", {})
        log_file = logging_cfg.get("file")
        resolved_log = self._resolve_project_path(log_file)
        if resolved_log:
            logging_cfg["file"] = str(resolved_log)

        return config

    def _init_components(self):
        """初始化所有子组件"""
        log_cfg = self.config.get("logging", {})
        setup_logger(
            "halberdstrike",
            level=log_cfg.get("level", "INFO"),
            log_file=log_cfg.get("file"),
            console=log_cfg.get("console", True),
        )

        self.provider = self._create_provider()
        self.context_manager = ContextManager(self.provider)

        storage_cfg = self.config.get("storage", {})
        self.db = Database(storage_cfg.get("database_path", "./data/halberdstrike.db"))
        self.db.connect()
        self.file_store = FileStore(
            storage_cfg.get("projects_dir", "./data/projects"),
            storage_cfg.get("reports_dir", "./data/reports"),
        )
        self.ptt_serializer = PTTSerializer(self.file_store)

        exec_cfg = self.config.get("execution", {})
        self.runner = CommandRunner(
            default_timeout=exec_cfg.get("default_timeout", 300),
            max_output_size=self.config.get("security", {}).get("max_output_size", 1048576),
        )

        sec_cfg = self.config.get("security", {})
        self.cmd_validator = CommandValidator(
            blocked_commands=sec_cfg.get("blocked_commands"),
        )

        self.reasoning: Optional[ReasoningModule] = None
        self.generation: Optional[GenerationModule] = None
        self.parsing: Optional[ParsingModule] = None

    def _create_provider(self) -> LLMProvider:
        return self._create_provider_from_config(self.config)

    @staticmethod
    def _create_provider_from_config(config: Dict[str, Any]) -> LLMProvider:
        llm_cfg = config.get("llm", {})
        provider_type = llm_cfg.get("provider", "openai")

        if provider_type == "ollama":
            ollama_cfg = llm_cfg.get("ollama", {})
            return OllamaProvider(
                base_url=ollama_cfg.get("base_url", "http://localhost:11434"),
                model=ollama_cfg.get("model", "qwen2.5:32b"),
                temperature=llm_cfg.get("temperature", 0.3),
                max_tokens=llm_cfg.get("max_tokens", 4096),
                context_window=llm_cfg.get("context_window", 32000),
            )
        else:
            return OpenAIProvider(
                api_key=llm_cfg.get("api_key", ""),
                base_url=llm_cfg.get("base_url", "https://api.openai.com/v1"),
                model=llm_cfg.get("model", "gpt-4o"),
                temperature=llm_cfg.get("temperature", 0.3),
                max_tokens=llm_cfg.get("max_tokens", 4096),
                context_window=llm_cfg.get("context_window", 128000),
            )

    def reload_runtime_config(self, new_config: Dict[str, Any]):
        """热重载配置并重建运行时依赖。"""
        if self.is_running:
            raise RuntimeError("任务执行中，无法热重载配置，请先停止任务")

        current_project = self.project
        current_tree = self.reasoning.tree if self.reasoning else None

        if hasattr(self.provider, "close"):
            self.provider.close()
        if hasattr(self, "db") and self.db:
            self.db.close()

        self.config = new_config
        self._parallel_workers = self.config.get("execution", {}).get("parallel_workers", 1)

        log_cfg = self.config.get("logging", {})
        setup_logger(
            "halberdstrike",
            level=log_cfg.get("level", "INFO"),
            log_file=log_cfg.get("file"),
            console=log_cfg.get("console", True),
        )

        self.provider = self._create_provider()
        self.context_manager = ContextManager(self.provider)

        storage_cfg = self.config.get("storage", {})
        self.db = Database(storage_cfg.get("database_path", "./data/halberdstrike.db"))
        self.db.connect()
        self.file_store = FileStore(
            storage_cfg.get("projects_dir", "./data/projects"),
            storage_cfg.get("reports_dir", "./data/reports"),
        )
        self.ptt_serializer = PTTSerializer(self.file_store)

        exec_cfg = self.config.get("execution", {})
        self.runner = CommandRunner(
            default_timeout=exec_cfg.get("default_timeout", 300),
            max_output_size=self.config.get("security", {}).get("max_output_size", 1048576),
        )
        sec_cfg = self.config.get("security", {})
        self.cmd_validator = CommandValidator(
            blocked_commands=sec_cfg.get("blocked_commands"),
        )

        self.reasoning = None
        self.generation = None
        self.parsing = None

        if current_project:
            self.project = current_project
            self.db.save_project(current_project)
            self.scope_validator = ScopeValidator(current_project.scope)

            self.reasoning = ReasoningModule(self.provider, self.context_manager)
            self.generation = GenerationModule(self.provider, self.context_manager, current_project.target)
            self.parsing = ParsingModule(self.provider, self.context_manager)

            if current_tree:
                self.reasoning.load_tree(current_tree)
                self.ptt_serializer.save(current_project.id, self.reasoning.tree)
        else:
            self.project = None

        logger.info("运行时配置已热重载")

    def set_approval_callback(self, callback):
        """设置人工审批回调函数

        callback(command, risk_level) -> 'approve' | 'reject' | 'modify:new_command'
        """
        self._approval_callback = callback

    # ── 工具产物清理 ──

    # 项目自身的保留文件/目录（不会被清理）
    _KEEP_NAMES = {
        "config", "src", "data", "tests", ".git", ".gitignore",
        "__pycache__", ".venv", "venv", "env",
        "README.md", "readme.md", "requirements.txt", "setup.py",
        "pyproject.toml", "Makefile", "Dockerfile", "docker-compose.yml",
        "docker-compose.yaml", "LICENSE", ".windsurf",
        "package.json", "package-lock.json", "tsconfig.json",
        "config.json", "settings.json",
    }
    # 工具生成文件的典型后缀（不含 .json，避免误删配置文件）
    _ARTIFACT_EXTS = {
        ".txt", ".html", ".xml", ".csv", ".log",
        ".gnmap", ".nmap", ".out", ".tmp", ".bak",
    }

    def _cleanup_tool_artifacts(self):
        """清理项目根目录下上次扫描生成的工具产物文件"""
        project_root = Path.cwd()
        removed = 0
        for item in project_root.iterdir():
            if item.is_dir():
                continue
            if item.name in self._KEEP_NAMES:
                continue
            if item.suffix.lower() in self._ARTIFACT_EXTS:
                try:
                    item.unlink()
                    removed += 1
                except OSError as e:
                    logger.debug(f"清理文件失败: {item.name} - {e}")
        if removed:
            logger.info(f"已清理 {removed} 个上次扫描的工具产物文件")

    # ── 项目管理 ──

    def create_project(self, name: str, target: str,
                       scope: Optional[List[str]] = None) -> Project:
        """创建新渗透测试项目"""
        if scope is None:
            scope = [target]

        project = Project(name=name, target=target, scope=scope)
        self.db.save_project(project)
        self.project = project

        self.scope_validator = ScopeValidator(scope)

        self.reasoning = ReasoningModule(self.provider, self.context_manager)
        self.generation = GenerationModule(self.provider, self.context_manager, target)
        self.parsing = ParsingModule(self.provider, self.context_manager)

        self.reasoning.init_session(target)
        self.ptt_serializer.save(project.id, self.reasoning.tree)

        logger.info(f"项目已创建: {name} -> {target}")
        return project

    def load_project(self, project_id: str) -> Optional[Project]:
        """加载已有项目"""
        project = self.db.get_project(project_id)
        if not project:
            logger.error(f"项目不存在: {project_id}")
            return None

        self.project = project
        self.scope_validator = ScopeValidator(project.scope)

        self.reasoning = ReasoningModule(self.provider, self.context_manager)
        self.generation = GenerationModule(self.provider, self.context_manager, project.target)
        self.parsing = ParsingModule(self.provider, self.context_manager)

        tree = self.ptt_serializer.load(project_id)
        if tree:
            self.reasoning.load_tree(tree)

        logger.info(f"项目已加载: {project.name}")
        return project

    # ── 主执行循环 ──

    def run(self, max_iterations: int = 50) -> bool:
        """启动主执行循环

        Returns: 是否正常完成
        """
        if not self.project or not self.reasoning:
            logger.error("请先创建或加载项目")
            return False

        self.is_running = True
        self.is_paused = False
        self.consecutive_failures = 0
        iteration = 0
        max_failures = self.config.get("execution", {}).get("max_consecutive_failures", 3)
        self._run_iteration_max = max_iterations
        self._activity_phase = "starting"
        self._activity_detail = "初始化扫描…"
        self._current_task_name = ""

        self._cleanup_tool_artifacts()

        logger.info("=" * 60)
        logger.info(f"开始渗透测试: {self.project.target}")
        logger.info("=" * 60)

        try:
            while self.is_running and iteration < max_iterations:
                if self.is_paused:
                    self._activity_phase = "paused"
                    self._activity_detail = "已暂停，等待恢复"
                    time.sleep(0.5)
                    continue

                iteration += 1
                self._run_iteration_current = iteration
                self._activity_phase = "reasoning"
                self._activity_detail = f"迭代 {iteration}/{max_iterations} · 选择下一任务…"
                logger.info(f"\n{'─' * 40} 迭代 {iteration}/{max_iterations} {'─' * 40}")

                # 处理暂存的人工指导
                if self._pending_guidance and self.reasoning:
                    for g in self._pending_guidance:
                        try:
                            result = self.reasoning.handle_user_guidance(g)
                            self.ptt_serializer.save(self.project.id, self.reasoning.tree)
                            logger.info(f"暂存指导已处理: {result.get('analysis', 'N/A')[:80]}")
                        except Exception as e:
                            logger.warning(f"处理暂存指导失败: {e}")
                    self._pending_guidance.clear()

                next_task = self.reasoning.get_next_task()
                if not next_task:
                    logger.info("所有任务已完成或无可执行任务")
                    self._activity_phase = "idle"
                    self._activity_detail = "任务队列已空或全部完成"
                    break

                logger.info(f"当前任务: [{next_task.id}] {next_task.name}")
                next_task.mark_in_progress()
                self._current_task_name = next_task.name

                self._activity_phase = "generating"
                self._activity_detail = f"LLM 生成命令 · {next_task.name[:80]}"

                gen_result = self.generation.generate_commands(
                    task_name=next_task.name,
                    task_description=next_task.description,
                    context_info=self._get_context_for_generation(),
                )

                steps = gen_result.get("steps", [])
                if not steps:
                    logger.warning("生成模块未返回有效步骤")
                    next_task.mark_failed("未生成有效执行步骤")
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= max_failures:
                        logger.warning(f"连续失败 {self.consecutive_failures} 次，暂停执行")
                        self.is_paused = True
                    continue

                self._activity_phase = "executing"
                self._activity_detail = f"执行工具命令 · {len(steps)} 个步骤"

                all_step_results, step_failed = self._execute_steps_parallel(
                    steps, next_task.id
                )

                combined_summary = self._combine_step_results(all_step_results)

                self._activity_phase = "parsing"
                self._activity_detail = "LLM 分析输出并更新任务树…"

                reasoning_result = self.reasoning.analyze_and_plan(
                    execution_result=combined_summary,
                    current_node_id=next_task.id,
                )

                self.ptt_serializer.save(self.project.id, self.reasoning.tree)

                # UCB 奖励反馈
                if step_failed:
                    self.consecutive_failures += 1
                    self.reasoning.tree.update_reward(next_task.id, -0.5)
                else:
                    self.consecutive_failures = 0
                    reward = 1.0
                    # 发现漏洞/凭据额外加分
                    for r in all_step_results:
                        reward += len(r.get("vulnerabilities", [])) * 2.0
                        reward += len(r.get("credentials", [])) * 3.0
                        reward += len(r.get("open_ports", [])) * 0.3
                    self.reasoning.tree.update_reward(next_task.id, reward)

                if self.consecutive_failures >= max_failures:
                    logger.warning(f"连续失败 {self.consecutive_failures} 次，暂停等待人工干预")
                    self.is_paused = True

                if reasoning_result.get("is_completed"):
                    logger.info("推理模块判断测试已完成")
                    break

        except KeyboardInterrupt:
            logger.info("用户中断执行")
        except Exception as e:
            logger.error(f"执行异常: {e}", exc_info=True)
        finally:
            self.is_running = False
            self._activity_phase = "idle"
            self._activity_detail = ""
            self._run_iteration_current = 0
            self._run_iteration_max = 0
            self._current_task_name = ""
            self.ptt_serializer.save(self.project.id, self.reasoning.tree)
            self.db.save_project(self.project)

        logger.info("=" * 60)
        logger.info("渗透测试执行结束")
        logger.info(f"PTT状态:\n{self.reasoning.tree.get_display_tree()}")
        logger.info("=" * 60)
        return True

    def pause(self):
        """暂停执行"""
        self.is_paused = True
        logger.info("执行已暂停")

    def resume(self):
        """恢复执行"""
        self.is_paused = False
        self.consecutive_failures = 0
        logger.info("执行已恢复")

    def stop(self):
        """停止执行"""
        self.is_running = False
        self._activity_phase = "stopping"
        self._activity_detail = "正在停止…"
        logger.info("执行已停止")

    def guide(self, guidance: str):
        """人工指导 —— 若推理模块已就绪则立即处理，否则暂存等待下次迭代"""
        if not guidance:
            return
        if self.reasoning and self.project:
            result = self.reasoning.handle_user_guidance(guidance)
            self.ptt_serializer.save(self.project.id, self.reasoning.tree)
            logger.info(f"人工指导已处理: {result.get('analysis', 'N/A')[:100]}")
        else:
            self._pending_guidance.append(guidance)
            logger.info(f"人工指导已暂存（待推理模块就绪）: {guidance[:80]}")

    def get_tree_display(self) -> str:
        """获取PTT可视化"""
        if not self.reasoning:
            return "PTT未初始化"
        return self.reasoning.tree.get_display_tree()

    # ── 并行执行 ──

    def _execute_steps_parallel(self, steps: List[Dict[str, Any]],
                                node_id: str) -> tuple[List[Dict[str, Any]], bool]:
        """并行执行多个步骤，返回 (结果列表, 是否有失败)"""
        approved_steps = []
        for step in steps:
            if self.is_paused or not self.is_running:
                break
            command = step.get("command", "")
            risk = step.get("risk_level", "low")
            if not command:
                continue
            approval = self._approve_command(command, risk)
            if approval == "reject":
                logger.info(f"命令被拒绝: {command[:80]}")
                continue
            elif approval.startswith("modify:"):
                command = approval[7:]
            approved_steps.append({**step, "command": command})

        if not approved_steps:
            return [], True

        results = []
        any_failed = False

        def _run_one(s: Dict[str, Any]) -> Dict[str, Any]:
            cmd = s["command"]
            risk = s.get("risk_level", "low")
            cfg_default = self.config.get("execution", {}).get("default_timeout", 300)
            timeout = min(s.get("timeout", cfg_default), cfg_default)
            exec_result = self._execute_command(cmd, timeout)
            with self._exec_lock:
                self._log_action(
                    ptt_node_id=node_id,
                    module=ModuleType.GENERATION,
                    action_type=ActionType.TOOL_EXEC,
                    command=cmd,
                    raw_output=exec_result.output[:5000],
                    risk_level=RiskLevel(risk) if risk in ('low', 'medium', 'high') else RiskLevel.LOW,
                    approved_by=ApprovalSource.AUTO if risk == "low" else ApprovalSource.USER,
                    duration=exec_result.duration,
                )
            adapter = get_adapter(cmd)
            adapter_parsed = {}
            if adapter:
                try:
                    adapter_parsed = adapter.parse_output(exec_result.output)
                except Exception:
                    pass
            adapter_hint = self._format_adapter_hint(adapter_parsed)

            tool_name = cmd.split()[0].split("/")[-1] if cmd else "unknown"
            raw_for_llm = exec_result.truncated_output(4000)
            if adapter_hint:
                raw_for_llm = f"[Adapter预解析]\n{adapter_hint}\n\n[原始输出]\n{raw_for_llm}"

            with self._exec_lock:
                parsed = self.parsing.parse_tool_output(
                    tool_name=tool_name,
                    command=cmd,
                    raw_output=raw_for_llm,
                )
            if adapter_parsed:
                parsed = self._merge_adapter_results(parsed, adapter_parsed)
            with self._exec_lock:
                self._extract_and_save_findings(parsed, node_id)
            return {"parsed": parsed, "failed": not exec_result.success}

        workers = min(self._parallel_workers, len(approved_steps))
        if workers <= 1:
            for s in approved_steps:
                r = _run_one(s)
                results.append(r["parsed"])
                if r["failed"]:
                    any_failed = True
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_run_one, s): s for s in approved_steps}
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                        results.append(r["parsed"])
                        if r["failed"]:
                            any_failed = True
                    except Exception as e:
                        logger.error(f"并行执行异常: {e}")
                        any_failed = True

        return results, any_failed

    # ── 内部方法 ──

    def _approve_command(self, command: str, risk_level: str) -> str:
        """命令审批流程"""
        is_safe, reason = self.cmd_validator.validate(command)
        if not is_safe:
            logger.warning(f"命令校验失败: {reason}")
            return "reject"

        if hasattr(self, 'scope_validator') and self.scope_validator:
            scope_ok, scope_reason = self.scope_validator.validate_command_target(command)
            if not scope_ok:
                logger.warning(f"范围校验失败: {scope_reason}")
                return "reject"

        auto_levels = self.config.get("execution", {}).get("auto_approve_risk_levels", ["low"])
        if risk_level in auto_levels:
            return "approve"

        if self._approval_callback:
            return self._approval_callback(command, risk_level)

        logger.warning(f"[需要审批但无回调] 风险: {risk_level} | 命令: {command} -> 默认拒绝")
        return "reject"

    def _execute_command(self, command: str, timeout: int) -> ExecutionResult:
        """执行命令"""
        max_timeout = self.config.get("execution", {}).get("max_timeout", 1800)
        timeout = min(timeout, max_timeout)
        return self.runner.execute(command, timeout=timeout)

    def _get_context_for_generation(self) -> str:
        """构建结构化知识库上下文，聚合端口/服务/漏洞/凭据视图"""
        if not self.project:
            return "暂无历史发现"

        parts = []

        # 1. 从数据库获取所有 findings 并分类聚合
        db_findings = self.db.get_findings(self.project.id)
        ports = []
        vulns = []
        creds = []
        other = []
        for f in db_findings:
            if f.type.value == "port":
                ports.append(f.title)
            elif f.type.value == "vuln":
                vulns.append(f"[{f.severity.value.upper()}] {f.title}")
            elif f.type.value == "credential":
                creds.append(f.title)
            else:
                other.append(f.title)

        if ports:
            parts.append("【已发现端口/服务】\n" + "\n".join(f"  - {p}" for p in ports[:20]))
        if vulns:
            parts.append("【已发现漏洞】\n" + "\n".join(f"  - {v}" for v in vulns[:15]))
        if creds:
            parts.append("【已发现凭据】\n" + "\n".join(f"  - {c}" for c in creds[:10]))
        if other:
            parts.append("【其他发现】\n" + "\n".join(f"  - {o}" for o in other[:10]))

        # 2. 从 PTT 获取最近的任务执行发现
        if self.reasoning:
            tree_findings = self.reasoning.tree.get_all_findings()
            if tree_findings:
                recent = tree_findings[-8:]
                parts.append("【最近任务发现】\n" + "\n".join(f"  - {f}" for f in recent))

        # 3. 从 action_logs 提取最近的命令摘要
        recent_logs = self.db.get_action_logs(self.project.id, limit=5)
        if recent_logs:
            cmd_lines = []
            for log in recent_logs:
                if log.command:
                    status = "✓" if log.duration_seconds > 0 else "✗"
                    cmd_lines.append(f"  {status} {log.command[:80]}")
            if cmd_lines:
                parts.append("【最近执行命令】\n" + "\n".join(cmd_lines))

        return "\n\n".join(parts) if parts else "暂无历史发现"

    def _combine_step_results(self, results: List[Dict[str, Any]]) -> str:
        """合并多个步骤的解析结果"""
        summaries = []
        all_findings = []
        for r in results:
            s = r.get("summary", "")
            if s:
                summaries.append(s)
            findings = r.get("key_findings", [])
            all_findings.extend(findings)

        parts = []
        if summaries:
            parts.append("执行摘要: " + " | ".join(summaries))
        if all_findings:
            parts.append("关键发现:\n" + "\n".join(f"- {f}" for f in all_findings[:15]))
        return "\n\n".join(parts) if parts else "无有效输出"

    # 用于从 key_findings 文本中推断严重性的关键词
    _SEV_KEYWORDS = {
        Severity.CRITICAL: ["rce", "remote code execution", "命令注入", "任意代码执行",
                            "unauthenticated rce", "反序列化"],
        Severity.HIGH: ["sql injection", "sql注入", "xss", "ssrf", "lfi", "rfi",
                        "文件包含", "任意文件读取", "认证绕过", "权限提升",
                        "privilege escalation", "credential", "凭据", "密码泄露",
                        "弱口令", "default password", "upload", "文件上传"],
        Severity.MEDIUM: ["csrf", "信息泄露", "information disclosure", "directory listing",
                          "目录遍历", "目录列表", "配置泄露", "版本泄露",
                          "header missing", "cors", "clickjacking"],
        Severity.LOW: ["cookie", "http only", "版本过旧", "deprecated"],
    }

    def _infer_severity(self, text: str) -> Severity:
        """根据关键词从文本中推断严重性等级"""
        lower = text.lower()
        for sev, keywords in self._SEV_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return sev
        return Severity.INFO

    def _extract_and_save_findings(self, parsed: Dict[str, Any], node_id: str):
        """从解析结果中提取并保存发现"""
        if not self.project:
            return

        batch: List[Finding] = []

        # 1. 漏洞
        for vuln in parsed.get("vulnerabilities", []):
            batch.append(Finding(
                project_id=self.project.id,
                ptt_node_id=node_id,
                type=FindingType.VULNERABILITY,
                severity=self._map_severity(vuln.get("severity", "info")),
                title=vuln.get("description", vuln.get("id", "未知漏洞"))[:200],
                description=str(vuln),
                cve_id=vuln.get("id"),
            ))

        # 2. 凭据
        for cred in parsed.get("credentials", []):
            batch.append(Finding(
                project_id=self.project.id,
                ptt_node_id=node_id,
                type=FindingType.CREDENTIAL,
                severity=Severity.HIGH,
                title=f"发现凭据: {cred.get('username', '?')}@{cred.get('service', '?')}",
                description=str(cred),
            ))

        # 3. 开放端口
        for port_info in parsed.get("open_ports", []):
            if isinstance(port_info, dict):
                batch.append(Finding(
                    project_id=self.project.id,
                    ptt_node_id=node_id,
                    type=FindingType.PORT,
                    severity=Severity.INFO,
                    title=f"端口 {port_info.get('port')}/{port_info.get('service', '?')} ({port_info.get('version', '')})",
                    description=str(port_info),
                ))

        # 4. 关键发现 —— 将 key_findings 中有价值的条目存为发现
        vuln_titles = {f.title for f in batch}
        for kf in parsed.get("key_findings", []):
            if not isinstance(kf, str) or len(kf) < 5:
                continue
            # 跳过纯信息性 / 已被上面覆盖的条目
            if kf in vuln_titles:
                continue
            sev = self._infer_severity(kf)
            ftype = FindingType.VULNERABILITY if sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM) else FindingType.MISC
            batch.append(Finding(
                project_id=self.project.id,
                ptt_node_id=node_id,
                type=ftype,
                severity=sev,
                title=kf[:200],
                description=f"来源: key_findings",
            ))

        # 5. 敏感路径
        for path_str in parsed.get("interesting_paths", []):
            if not isinstance(path_str, str) or len(path_str) < 2:
                continue
            batch.append(Finding(
                project_id=self.project.id,
                ptt_node_id=node_id,
                type=FindingType.FILE,
                severity=Severity.LOW,
                title=f"敏感路径: {path_str}"[:200],
                description=f"发现敏感路径: {path_str}",
            ))

        # 批量入库
        if batch:
            self.db.save_findings_batch(batch)
            logger.debug(f"提取并保存 {len(batch)} 条发现")

    @staticmethod
    def _format_adapter_hint(adapter_parsed: Dict[str, Any]) -> str:
        """将适配器预解析结果格式化为 LLM 可读的提示文本"""
        if not adapter_parsed:
            return ""
        parts = []
        # 开放端口
        for p in adapter_parsed.get("open_ports", []):
            if isinstance(p, dict):
                parts.append(f"端口 {p.get('port')}/{p.get('protocol', 'tcp')} "
                             f"服务={p.get('service', '?')} 版本={p.get('version', '?')}")
        # 漏洞
        for v in adapter_parsed.get("vulnerabilities", []):
            if isinstance(v, dict):
                parts.append(f"漏洞 [{v.get('severity', 'info')}] {v.get('id', '')}: "
                             f"{v.get('description', '')[:120]}")
        # 目录/路径 / DNS 子域
        for d in adapter_parsed.get("directories", adapter_parsed.get("found_paths", [])):
            if isinstance(d, dict):
                if d.get("status") == "dns":
                    parts.append(f"子域名 {d.get('path', '')}")
                else:
                    parts.append(f"路径 {d.get('path', d.get('url', ''))} "
                                 f"状态={d.get('status', '?')}")
            elif isinstance(d, str):
                parts.append(f"路径 {d}")
        # 凭据
        for c in adapter_parsed.get("credentials", []):
            if isinstance(c, dict):
                parts.append(f"凭据 {c.get('username', '?')}:{c.get('password', '?')} "
                             f"@{c.get('service', '?')}")
        # 通用摘要
        summary = adapter_parsed.get("summary", "")
        if summary and not parts:
            parts.append(summary)
        return "\n".join(parts[:30])

    @staticmethod
    def _merge_adapter_results(llm_parsed: Dict[str, Any],
                               adapter_parsed: Dict[str, Any]) -> Dict[str, Any]:
        """将适配器结构化数据合并到 LLM 解析结果中（去重补充）"""
        if not adapter_parsed:
            return llm_parsed

        # 合并 open_ports
        existing_ports = {str(p.get("port")) for p in llm_parsed.get("open_ports", [])
                          if isinstance(p, dict)}
        for p in adapter_parsed.get("open_ports", []):
            if isinstance(p, dict) and str(p.get("port")) not in existing_ports:
                llm_parsed.setdefault("open_ports", []).append(p)

        # 合并 vulnerabilities
        existing_vulns = {v.get("id", "") for v in llm_parsed.get("vulnerabilities", [])
                          if isinstance(v, dict)}
        for v in adapter_parsed.get("vulnerabilities", []):
            if isinstance(v, dict) and v.get("id", "") not in existing_vulns:
                llm_parsed.setdefault("vulnerabilities", []).append(v)

        # 合并 credentials
        existing_creds = {f"{c.get('username')}@{c.get('service')}"
                          for c in llm_parsed.get("credentials", []) if isinstance(c, dict)}
        for c in adapter_parsed.get("credentials", []):
            if isinstance(c, dict):
                key = f"{c.get('username')}@{c.get('service')}"
                if key not in existing_creds:
                    llm_parsed.setdefault("credentials", []).append(c)

        return llm_parsed

    def _map_severity(self, level: str) -> Severity:
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        return mapping.get(level.lower(), Severity.INFO)

    def _log_action(self, ptt_node_id: str, module: ModuleType,
                    action_type: ActionType, command: str = "",
                    raw_output: str = "", risk_level: RiskLevel = RiskLevel.LOW,
                    approved_by: ApprovalSource = ApprovalSource.AUTO,
                    duration: float = 0.0):
        """记录操作日志"""
        if not self.project:
            return
        log = ActionLog(
            project_id=self.project.id,
            ptt_node_id=ptt_node_id,
            module=module,
            action_type=action_type,
            command=command,
            raw_output=raw_output,
            risk_level=risk_level,
            approved_by=approved_by,
            duration_seconds=duration,
        )
        self.db.save_action_log(log)

    def cleanup(self):
        """清理资源"""
        if hasattr(self.provider, 'close'):
            self.provider.close()
        self.db.close()
        logger.info("资源已清理")
