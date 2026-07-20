"""Web 仪表盘服务 - Flask 后端 + SSE 实时推送 + 项目管理"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, session, url_for

from src.utils.logger import get_logger

logger = get_logger("halberdstrike.web")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


class WebDashboard:
    """Web 仪表盘服务器

    功能:
    - 实时进度展示 (SSE)
    - PTT 任务树可视化
    - 发现/漏洞列表
    - 操作日志
    - 控制面板 (暂停/恢复/停止/指导)
    - 项目管理 (列表/创建/加载/删除/启动扫描)
    """

    def __init__(self, orchestrator=None, host: str = "localhost", port: int = 5000,
                 config_path: Optional[str] = None):
        self.orch = orchestrator
        self.host = host
        self.port = port
        self._config_path = config_path
        self._run_thread: Optional[threading.Thread] = None
        self._app = self._create_app()
        self._sse_clients: List[queue.Queue] = []
        self._sse_lock = threading.Lock()
        self._server_thread: Optional[threading.Thread] = None
        self._event_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._server_ready = threading.Event()
        self._server_error: Optional[BaseException] = None

        if self.orch is None:
            self._init_standalone()

    def _init_standalone(self):
        """独立模式初始化 - 创建 Orchestrator 实例"""
        try:
            from src.core.orchestrator import Orchestrator
            self.orch = Orchestrator(config_path=self._config_path)
            self.orch.set_approval_callback(self._web_approval_callback)
            logger.info("独立模式: Orchestrator 已初始化")
        except Exception as e:
            logger.error(f"初始化 Orchestrator 失败: {e}")
            raise

    @staticmethod
    def _web_approval_callback(command: str, risk_level: str) -> str:
        """Web 模式下自动审批 medium 及以下，拒绝 high"""
        if risk_level in ("low", "medium"):
            return "approve"
        return "reject"

    def _create_app(self) -> Flask:
        app = Flask(
            __name__,
            template_folder=str(TEMPLATE_DIR),
            static_folder=str(STATIC_DIR),
        )
        app.config["JSON_AS_ASCII"] = False
        app.config["SECRET_KEY"] = "halberdstrike_web_secret_key_2026"

        self._users = {
            "admin": "e10adc3949ba59abbe56e057f20f883e"
        }

        def login_required(f):
            def decorated(*args, **kwargs):
                if not session.get('logged_in'):
                    return redirect(url_for('login'))
                return f(*args, **kwargs)
            decorated.__name__ = f.__name__
            return decorated

        # ── 页面路由 ──

        @app.route("/login")
        def login():
            if session.get('logged_in'):
                return redirect(url_for('index'))
            return render_template("login.html")

        @app.route("/")
        @login_required
        def index():
            return render_template("index.html")

        # ── 登录 API ──

        @app.route("/api/login", methods=["POST"])
        def api_login():
            data = request.get_json(silent=True) or {}
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()

            if not username or not password:
                return jsonify({"ok": False, "message": "用户名或密码不能为空"})

            stored_hash = self._users.get(username)
            if stored_hash is None:
                return jsonify({"ok": False, "message": "用户不存在"})

            password_hash = hashlib.md5(password.encode()).hexdigest()
            if password_hash != stored_hash:
                return jsonify({"ok": False, "message": "密码错误"})

            session['logged_in'] = True
            session['username'] = username
            logger.info(f"用户登录成功: {username}")
            return jsonify({"ok": True, "message": "登录成功"})

        @app.route("/api/logout", methods=["POST"])
        def api_logout():
            session.clear()
            return jsonify({"ok": True, "message": "已登出"})

        @app.route("/api/change_password", methods=["POST"])
        @login_required
        def api_change_password():
            data = request.get_json(silent=True) or {}
            logger.info(f"change_password received data: {data}")
            old_password = data.get("current_password", "").strip() or data.get("old_password", "").strip()
            new_password = data.get("new_password", "").strip()
            logger.info(f"old_password: '{old_password}', new_password: '{new_password}'")

            if not old_password or not new_password:
                return jsonify({"ok": False, "message": "密码不能为空"})

            if len(new_password) < 6:
                return jsonify({"ok": False, "message": "新密码至少6位"})

            username = session.get('username')
            stored_hash = self._users.get(username)
            old_hash = hashlib.md5(old_password.encode()).hexdigest()

            if old_hash != stored_hash:
                return jsonify({"ok": False, "message": "原密码错误"})

            new_hash = hashlib.md5(new_password.encode()).hexdigest()
            self._users[username] = new_hash
            logger.info(f"用户修改密码成功: {username}")
            return jsonify({"ok": True, "message": "密码修改成功"})

        @app.route("/api/check_login")
        def api_check_login():
            return jsonify({"logged_in": session.get('logged_in', False)})

        # ── API 路由 ──

        @app.route("/api/status")
        @login_required
        def api_status():
            """获取当前运行状态"""
            return jsonify(self._get_status())

        @app.route("/api/tree")
        @login_required
        def api_tree():
            """获取 PTT 任务树"""
            return jsonify(self._get_tree_data())

        @app.route("/api/findings")
        @login_required
        def api_findings():
            """获取发现列表"""
            return jsonify(self._get_findings())

        @app.route("/api/logs")
        @login_required
        def api_logs():
            """获取操作日志"""
            limit = request.args.get("limit", 50, type=int)
            return jsonify(self._get_logs(limit))

        @app.route("/api/progress")
        @login_required
        def api_progress():
            """获取进程进度"""
            from src.tools.progress import ProcessManager
            mgr = ProcessManager()
            return jsonify(mgr.get_dashboard())

        @app.route("/api/charts")
        @login_required
        def api_charts():
            """获取图表数据"""
            return jsonify(self._get_chart_data())

        @app.route("/api/token_stats")
        @login_required
        def api_token_stats():
            """获取 LLM Token 实时统计"""
            return jsonify(self._get_token_stats())

        @app.route("/api/system_stats")
        @login_required
        def api_system_stats():
            """获取系统资源监控数据"""
            return jsonify(self._get_system_stats())

        @app.route("/api/control", methods=["POST"])
        @login_required
        def api_control():
            """控制面板操作"""
            data = request.get_json(silent=True) or {}
            action = data.get("action", "")
            return jsonify(self._handle_control(action, data))

        # ── 项目管理 API ──

        @app.route("/api/projects")
        @login_required
        def api_projects():
            """列出所有项目"""
            return jsonify(self._list_projects())

        @app.route("/api/projects", methods=["POST"])
        @login_required
        def api_create_project():
            """创建新项目"""
            data = request.get_json(silent=True) or {}
            return jsonify(self._create_project(data))

        @app.route("/api/projects/<project_id>/load", methods=["POST"])
        @login_required
        def api_load_project(project_id):
            """加载已有项目"""
            return jsonify(self._load_project(project_id))

        @app.route("/api/projects/<project_id>/delete", methods=["POST"])
        @login_required
        def api_delete_project(project_id):
            """删除项目"""
            return jsonify(self._delete_project(project_id))

        @app.route("/api/projects/<project_id>/start", methods=["POST"])
        @login_required
        def api_start_scan(project_id):
            """启动渗透测试"""
            data = request.get_json(silent=True) or {}
            max_iter = data.get("max_iterations", 50)
            return jsonify(self._start_scan(project_id, max_iter))

        @app.route("/api/projects/<project_id>/report", methods=["POST"])
        @login_required
        def api_generate_report(project_id):
            """生成渗透测试报告"""
            return jsonify(self._generate_report(project_id))

        @app.route("/api/download_report")
        @login_required
        def api_download_report():
            """下载报告文件"""
            file_path = request.args.get("path", "")
            p = Path(file_path).resolve()
            # 安全校验：仅允许下载 reports 目录下的文件
            reports_root = self.orch.file_store.reports_dir.resolve()
            if not file_path or not p.exists() or not str(p).startswith(str(reports_root)):
                return jsonify({"ok": False, "message": "文件不存在或路径非法"}), 404
            return send_file(str(p), as_attachment=True, download_name=p.name)

        # ── 报告列表 API ──

        @app.route("/api/reports")
        @login_required
        def api_list_reports():
            """列出所有已生成的报告文件"""
            return jsonify(self._list_reports())

        # ── 配置管理 API ──

        @app.route("/api/config")
        @login_required
        def api_get_config():
            """读取当前配置"""
            return jsonify(self._get_config())

        @app.route("/api/config", methods=["POST"])
        @login_required
        def api_save_config():
            """保存配置到 config.yaml"""
            data = request.get_json(silent=True) or {}
            return jsonify(self._save_config(data))

        @app.route("/api/config/test_llm", methods=["POST"])
        @login_required
        def api_test_llm_config():
            """测试当前提交的 LLM 配置是否可用"""
            data = request.get_json(silent=True) or {}
            return jsonify(self._test_llm_config(data))

        # ── SSE 实时推送 ──

        @app.route("/api/events")
        @login_required
        def api_events():
            """Server-Sent Events 实时推送"""
            def stream():
                q = queue.Queue(maxsize=100)
                with self._sse_lock:
                    self._sse_clients.append(q)
                try:
                    # 发送初始状态
                    yield f"data: {json.dumps(self._get_full_state(), ensure_ascii=False)}\n\n"
                    while not self._stop_event.is_set():
                        try:
                            msg = q.get(timeout=1)
                            yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                        except queue.Empty:
                            # 心跳
                            yield ": heartbeat\n\n"
                except GeneratorExit:
                    pass
                finally:
                    with self._sse_lock:
                        if q in self._sse_clients:
                            self._sse_clients.remove(q)

            return Response(
                stream(),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                },
            )

        return app

    # ── 数据获取 ──

    def _get_status(self) -> Dict[str, Any]:
        project = self.orch.project
        orch = self.orch
        return {
            "project": {
                "id": project.id if project else None,
                "name": project.name if project else "未加载",
                "target": project.target if project else "",
                "status": project.status.value if project else "inactive",
            },
            "is_running": orch.is_running,
            "is_paused": orch.is_paused,
            "consecutive_failures": orch.consecutive_failures,
            "timestamp": datetime.now().isoformat(),
            "run_progress": {
                "phase": getattr(orch, "_activity_phase", "idle"),
                "detail": getattr(orch, "_activity_detail", ""),
                "iteration": getattr(orch, "_run_iteration_current", 0),
                "iteration_max": getattr(orch, "_run_iteration_max", 0),
                "task_name": getattr(orch, "_current_task_name", ""),
            },
        }

    def _get_tree_data(self) -> Dict[str, Any]:
        if not self.orch.reasoning or not self.orch.reasoning.tree:
            return {"nodes": [], "display": "PTT 未初始化"}

        tree = self.orch.reasoning.tree
        root = tree.root

        def node_to_dict(node) -> Dict:
            return {
                "id": node.id,
                "name": node.name,
                "description": node.description,
                "status": node.status.value,
                "priority": node.priority,
                "findings": node.findings[-5:] if node.findings else [],
                "children": [node_to_dict(c) for c in node.children],
            }

        return {
            "root": node_to_dict(root),
            "display": tree.get_display_tree(),
        }

    def _get_findings(self) -> List[Dict]:
        if not self.orch.project:
            return []
        findings = self.orch.db.get_findings(self.orch.project.id)
        return [
            {
                "id": f.id[:8],
                "type": f.type.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description[:200],
                "cve_id": f.cve_id,
                "timestamp": str(f.timestamp)[:19],
            }
            for f in findings
        ]

    def _get_logs(self, limit: int = 50) -> List[Dict]:
        if not self.orch.project:
            return []
        logs = self.orch.db.get_action_logs(self.orch.project.id, limit=limit)
        return [
            {
                "id": log.id[:8],
                "module": log.module.value,
                "action_type": log.action_type.value,
                "command": (log.command or "")[:120],
                "risk_level": log.risk_level.value,
                "approved_by": log.approved_by.value,
                "duration": log.duration_seconds,
                "timestamp": str(log.timestamp)[:19],
            }
            for log in logs
        ]

    def _get_chart_data(self) -> Dict[str, Any]:
        """获取图表所需的聚合数据"""
        findings = self._get_findings()
        logs = self._get_logs(200)
        tree = self._get_tree_data()

        # 1) 漏洞严重级别分布 (Doughnut)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # 2) 发现类型分布 (Polar Area)
        type_counts: Dict[str, int] = {}
        for f in findings:
            t = f.get("type", "misc")
            type_counts[t] = type_counts.get(t, 0) + 1

        # 3) 任务状态分布 (Doughnut)
        task_status = {"pending": 0, "in_progress": 0, "completed": 0, "failed": 0, "skipped": 0}
        def walk_tree(node):
            if not node:
                return
            s = node.get("status", "pending")
            if s in task_status:
                task_status[s] += 1
            for c in node.get("children", []):
                walk_tree(c)
        walk_tree(tree.get("root"))

        # 4) 命令执行时间线 (Line)
        timeline: List[Dict] = []
        for log in reversed(logs):
            if log.get("action_type") == "tool_exec" and log.get("command"):
                timeline.append({
                    "time": log.get("timestamp", ""),
                    "duration": log.get("duration", 0),
                    "command": log.get("command", "")[:40],
                    "risk": log.get("risk_level", "low"),
                })

        # 5) 风险级别分布 (Bar)
        risk_counts = {"low": 0, "medium": 0, "high": 0}
        for log in logs:
            r = log.get("risk_level", "low")
            if r in risk_counts:
                risk_counts[r] += 1

        # 6) Token 统计
        token_stats = self._get_token_stats()

        return {
            "severity_distribution": severity_counts,
            "finding_types": type_counts,
            "task_status": task_status,
            "execution_timeline": timeline[-30:],
            "risk_distribution": risk_counts,
            "token_stats": token_stats,
        }

    def _get_token_stats(self) -> Dict[str, Any]:
        """获取 LLM Token 实时统计"""
        try:
            stats = self.orch.provider.usage_stats.to_dict()
            # 添加 context_manager 的 per-session 统计
            if hasattr(self.orch, 'context_manager') and self.orch.context_manager:
                ctx = self.orch.context_manager
                session_count = len(ctx._sessions) if hasattr(ctx, '_sessions') else 0
                stats["active_sessions"] = session_count
            else:
                stats["active_sessions"] = 0
            return stats
        except Exception as e:
            logger.debug(f"获取 token 统计失败: {e}")
            return {
                "prompt_tokens": 0, "completion_tokens": 0,
                "total_tokens": 0, "requests": 0,
                "failed": 0, "retries": 0,
                "avg_latency": 0, "active_sessions": 0,
            }

    def _get_system_stats(self) -> Dict[str, Any]:
        """获取系统 CPU / 内存 / 网络实时数据"""
        import psutil
        try:
            cpu_percent = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()
            return {
                "cpu_percent": cpu_percent,
                "mem_total_gb": round(mem.total / (1024 ** 3), 1),
                "mem_used_gb": round(mem.used / (1024 ** 3), 1),
                "mem_percent": mem.percent,
                "net_sent_mb": round(net.bytes_sent / (1024 ** 2), 1),
                "net_recv_mb": round(net.bytes_recv / (1024 ** 2), 1),
            }
        except Exception as e:
            logger.debug(f"获取系统状态失败: {e}")
            return {
                "cpu_percent": 0, "mem_total_gb": 0, "mem_used_gb": 0,
                "mem_percent": 0, "net_sent_mb": 0, "net_recv_mb": 0,
            }

    def _get_full_state(self) -> Dict[str, Any]:
        """获取完整状态（初始推送用）"""
        from src.tools.progress import ProcessManager
        return {
            "type": "full_state",
            "status": self._get_status(),
            "tree": self._get_tree_data(),
            "findings": self._get_findings(),
            "logs": self._get_logs(30),
            "progress": ProcessManager().get_dashboard(),
            "charts": self._get_chart_data(),
        }

    # ── 控制操作 ──

    def _handle_control(self, action: str, data: Dict) -> Dict:
        if not self.orch:
            return {"ok": False, "message": "Orchestrator 未初始化"}
        try:
            if action == "pause":
                self.orch.pause()
                return {"ok": True, "message": "已暂停"}
            elif action == "resume":
                self.orch.resume()
                return {"ok": True, "message": "已恢复"}
            elif action == "stop":
                self.orch.stop()
                return {"ok": True, "message": "已停止"}
            elif action == "guide":
                guidance = data.get("guidance", "")
                if not guidance:
                    return {"ok": False, "message": "缺少 guidance 参数"}
                self.orch.guide(guidance)
                queued = not (self.orch.reasoning and self.orch.project)
                msg = f"指导已暂存（等待扫描开始）: {guidance[:50]}" if queued else f"指导已提交: {guidance[:50]}"
                return {"ok": True, "message": msg}
            return {"ok": False, "message": f"未知操作: {action}"}
        except Exception as e:
            logger.error(f"控制操作失败: action={action}, error={e}", exc_info=True)
            return {"ok": False, "message": f"操作失败: {e}"}

    # ── 项目管理 ──

    def _list_projects(self) -> List[Dict]:
        """列出所有项目"""
        try:
            projects = self.orch.db.list_projects()
            return [
                {
                    "id": p.id,
                    "name": p.name,
                    "target": p.target,
                    "scope": p.scope,
                    "status": p.status.value,
                    "created_at": str(p.created_at)[:19],
                    "updated_at": str(p.updated_at)[:19],
                    "is_current": (self.orch.project and self.orch.project.id == p.id),
                }
                for p in projects
            ]
        except Exception as e:
            logger.error(f"列出项目失败: {e}")
            return []

    def _create_project(self, data: Dict) -> Dict:
        """创建新项目"""
        name = data.get("name", "").strip()
        target = data.get("target", "").strip()
        scope = data.get("scope", [])

        if not name or not target:
            return {"ok": False, "message": "name 和 target 为必填项"}

        if not scope:
            scope = [target]
        elif isinstance(scope, str):
            scope = [s.strip() for s in scope.split(",") if s.strip()]

        try:
            project = self.orch.create_project(name, target, scope)
            return {
                "ok": True,
                "message": f"项目已创建: {project.id}",
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "target": project.target,
                },
            }
        except Exception as e:
            logger.error(f"创建项目失败: {e}")
            return {"ok": False, "message": f"创建失败: {e}"}

    def _load_project(self, project_id: str) -> Dict:
        """加载已有项目"""
        try:
            if self.orch.is_running:
                return {"ok": False, "message": "当前有任务正在运行，请先停止"}

            project = self.orch.load_project(project_id)
            if not project:
                return {"ok": False, "message": f"项目不存在: {project_id}"}
            return {
                "ok": True,
                "message": f"已加载: {project.name}",
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "target": project.target,
                },
            }
        except Exception as e:
            logger.error(f"加载项目失败: {e}")
            return {"ok": False, "message": f"加载失败: {e}"}

    def _delete_project(self, project_id: str) -> Dict:
        """删除项目"""
        try:
            if self.orch.project and self.orch.project.id == project_id:
                if self.orch.is_running:
                    return {"ok": False, "message": "不能删除正在运行的项目"}
                self.orch.project = None
                self.orch.reasoning = None

            self.orch.db.delete_project(project_id)
            return {"ok": True, "message": "项目已删除"}
        except Exception as e:
            logger.error(f"删除项目失败: {e}")
            return {"ok": False, "message": f"删除失败: {e}"}

    def _start_scan(self, project_id: str, max_iterations: int = 50) -> Dict:
        """启动渗透测试扫描"""
        try:
            if self.orch.is_running:
                return {"ok": False, "message": "已有任务正在运行"}

            if not self.orch.project or self.orch.project.id != project_id:
                project = self.orch.load_project(project_id)
                if not project:
                    return {"ok": False, "message": f"项目不存在: {project_id}"}

            if self._run_thread and self._run_thread.is_alive():
                return {"ok": False, "message": "扫描线程仍在运行"}

            self._run_thread = threading.Thread(
                target=self._run_scan_thread,
                args=(max_iterations,),
                daemon=True,
                name="web-scan",
            )
            self._run_thread.start()
            return {"ok": True, "message": f"扫描已启动 (max={max_iterations})"}
        except Exception as e:
            logger.error(f"启动扫描失败: {e}")
            return {"ok": False, "message": f"启动失败: {e}"}

    def _run_scan_thread(self, max_iterations: int):
        """后台线程运行扫描"""
        try:
            self.orch.run(max_iterations=max_iterations)
        except Exception as e:
            logger.error(f"扫描异常: {e}", exc_info=True)

    def _generate_report(self, project_id: str) -> Dict:
        """生成渗透测试报告"""
        try:
            if not self.orch.project or self.orch.project.id != project_id:
                project = self.orch.load_project(project_id)
                if not project:
                    return {"ok": False, "message": f"项目不存在: {project_id}"}

            from src.reporting.generator import ReportGenerator
            findings = self.orch.db.get_findings(project_id)
            logs = self.orch.db.get_action_logs(project_id, limit=200)
            gen = ReportGenerator(self.orch.provider, self.orch.file_store)
            path = gen.generate(
                project=self.orch.project,
                tree=self.orch.reasoning.tree if self.orch.reasoning else None,
                findings=findings,
                action_logs=logs,
            )
            return {"ok": True, "message": f"报告已生成", "path": str(path)}
        except Exception as e:
            logger.error(f"生成报告失败: {e}")
            return {"ok": False, "message": f"生成失败: {e}"}

    # ── 报告管理 ──

    def _list_reports(self) -> Dict[str, Any]:
        """扫描 reports 目录，列出所有已生成的报告文件"""
        try:
            reports_dir = self.orch.file_store.reports_dir
            if not reports_dir.exists():
                return {"ok": True, "reports": []}

            reports = []
            for proj_dir in sorted(reports_dir.iterdir(), reverse=True):
                if not proj_dir.is_dir():
                    continue
                # 尝试查找项目名称
                proj = self.orch.db.get_project(proj_dir.name)
                proj_name = proj.name if proj else proj_dir.name

                for f in sorted(proj_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                    if f.is_file():
                        stat = f.stat()
                        reports.append({
                            "filename": f.name,
                            "project_id": proj_dir.name,
                            "project_name": proj_name,
                            "path": str(f.resolve()),
                            "size_kb": round(stat.st_size / 1024, 1),
                            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        })
            return {"ok": True, "reports": reports}
        except Exception as e:
            logger.error(f"列出报告失败: {e}")
            return {"ok": False, "reports": [], "message": str(e)}

    # ── 配置管理 ──

    def _get_config(self) -> Dict[str, Any]:
        """读取 config.yaml 返回配置字典"""
        import yaml
        config_path = self._resolve_config_path()
        try:
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                # 隐藏 api_key 中间部分
                api_key = cfg.get("llm", {}).get("api_key", "")
                if len(api_key) > 10:
                    cfg["llm"]["api_key"] = api_key[:6] + "****" + api_key[-4:]
                return {"ok": True, "config": cfg}
            return {"ok": False, "message": "配置文件不存在"}
        except Exception as e:
            logger.error(f"读取配置失败: {e}")
            return {"ok": False, "message": str(e)}

    def _save_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """保存配置到 config.yaml 并热重载关键参数"""
        import yaml
        config_path = self._resolve_config_path()
        try:
            # 读取原始配置以保留完整 api_key
            old_cfg = {}
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    old_cfg = yaml.safe_load(f) or {}

            # 如果前端传来的 api_key 包含 **** 则保留原值
            new_api_key = new_config.get("llm", {}).get("api_key", "")
            if "****" in new_api_key:
                new_config.setdefault("llm", {})["api_key"] = old_cfg.get("llm", {}).get("api_key", "")

            # 写入文件
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(new_config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            logger.info("配置已保存到 config.yaml")

            self.orch.reload_runtime_config(new_config)

            return {"ok": True, "message": "配置已保存并生效"}
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
            return {"ok": False, "message": str(e)}

    def _resolve_config_path(self) -> Path:
        config_path = Path(self._config_path) if self._config_path else PROJECT_ROOT / "config" / "config.yaml"
        if not config_path.is_absolute():
            config_path = PROJECT_ROOT / config_path
        return config_path.resolve()

    def _test_llm_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """使用临时 provider 测试 LLM 配置可用性。"""
        config = payload.get("config") if isinstance(payload, dict) else None
        if not isinstance(config, dict):
            config = self.orch.config

        provider = None
        try:
            llm_cfg = config.get("llm", {})
            provider_name = llm_cfg.get("provider", "openai")
            api_key = llm_cfg.get("api_key", "").strip()
            base_url = llm_cfg.get("base_url", "")
            model = llm_cfg.get("model", "")

            if not base_url:
                return {"ok": False, "message": "基础地址不能为空"}
            
            if not model:
                return {"ok": False, "message": "模型名称不能为空"}

            if provider_name == "openai" and not api_key:
                return {"ok": False, "message": "API Key 不能为空"}

            provider = self.orch._create_provider_from_config(config)
            logger.info(f"[DEBUG] Provider 创建成功: {provider_name}, model={model}, base_url={base_url}")
            
            try:
                raw_reply = provider.chat(
                    [
                        {"role": "system", "content": "你是 HalberdStrike 的连通性测试助手。"},
                        {"role": "user", "content": "请仅回复 TEST_OK"},
                    ],
                    temperature=0,
                    max_tokens=100,
                )
                logger.info(f"[DEBUG] 原始响应: {repr(raw_reply)}")
                reply = raw_reply.strip()
                logger.info(f"[DEBUG] 处理后响应: {repr(reply)}")

                if not reply:
                    return {"ok": False, "message": "LLM 未返回内容"}
            except Exception as chat_e:
                logger.error(f"[DEBUG] 聊天请求失败: {chat_e}", exc_info=True)
                raise

            return {
                "ok": True,
                "message": f"连接成功: {provider_name} / {provider.model}",
                "reply": reply[:120],
            }
        except Exception as e:
            logger.error(f"LLM 配置测试失败: {e}", exc_info=True)
            error_msg = str(e)
            if "401" in error_msg or "Unauthorized" in error_msg or "api_key" in error_msg.lower():
                error_msg = "API Key 无效或过期，请检查密钥"
            elif "404" in error_msg or "not found" in error_msg.lower():
                error_msg = "模型不存在，请检查模型名称"
            elif "connection refused" in error_msg.lower() or "timed out" in error_msg.lower():
                error_msg = "网络连接失败，请检查基础地址和网络"
            elif "SSLError" in error_msg or "certificate" in error_msg.lower():
                error_msg = "SSL 证书验证失败，尝试使用 http 或检查证书配置"
            else:
                error_msg = f"连接失败: {error_msg[:100]}"
            return {"ok": False, "message": error_msg}
        finally:
            if provider and hasattr(provider, "close"):
                provider.close()

    # ── SSE 广播 ──

    def broadcast(self, event: Dict[str, Any]):
        """向所有 SSE 客户端广播事件"""
        with self._sse_lock:
            dead = []
            for q in self._sse_clients:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._sse_clients.remove(q)

    def _event_loop(self):
        """定时广播状态更新"""
        while not self._stop_event.is_set():
            try:
                from src.tools.progress import ProcessManager
                state = {
                    "type": "update",
                    "status": self._get_status(),
                    "progress": ProcessManager().get_dashboard(),
                }
                self.broadcast(state)
            except Exception as e:
                logger.debug(f"SSE 广播异常: {e}")
            # 扫描进行中时提高刷新频率，便于看到 LLM 阶段与命令进度
            try:
                interval = 1.0 if self.orch.is_running else 2.0
            except Exception:
                interval = 2.0
            self._stop_event.wait(interval)

    # ── 服务器生命周期 ──

    def start(self):
        """在后台线程启动 Web 服务"""
        self._stop_event.clear()
        self._server_ready.clear()
        self._server_error = None

        self._server_thread = threading.Thread(
            target=self._run_server, daemon=True, name="web-dashboard"
        )
        self._server_thread.start()

        if not self._server_ready.wait(timeout=10):
            raise RuntimeError(f"Web 服务启动超时: http://{self.host}:{self.port}")
        if self._server_error:
            raise RuntimeError(f"Web 服务启动失败: {self._server_error}") from self._server_error

        self._event_thread = threading.Thread(
            target=self._event_loop, daemon=True, name="web-events"
        )
        self._event_thread.start()

        logger.info(f"Web 仪表盘已启动: http://{self.host}:{self.port}")

    def _run_server(self):
        """运行 Flask 服务"""
        logger.info(f"[DEBUG] 开始创建 Web 服务器: {self.host}:{self.port}")
        try:
            from werkzeug.serving import make_server
            logger.info("[DEBUG] werkzeug.serving.make_server 导入成功")
            self._werkzeug_server = make_server(
                self.host, self.port, self._app, threaded=True
            )
            logger.info(f"[DEBUG] Web 服务器创建成功: {self.host}:{self.port}")
            self._server_ready.set()
            logger.info("[DEBUG] _server_ready 事件已设置")
            self._werkzeug_server.serve_forever()
        except ImportError as e:
            logger.error(f"[DEBUG] 导入错误: {e}", exc_info=True)
            self._server_error = e
            self._server_ready.set()
        except OSError as e:
            logger.error(f"[DEBUG] 网络错误: {e}", exc_info=True)
            self._server_error = e
            self._server_ready.set()
        except Exception as e:
            logger.error(f"[DEBUG] Web 服务线程异常: {e}", exc_info=True)
            self._server_error = e
            self._server_ready.set()

    def stop(self):
        """停止 Web 服务"""
        self._stop_event.set()
        if hasattr(self, '_werkzeug_server'):
            self._werkzeug_server.shutdown()
        logger.info("Web 仪表盘已停止")
