"""HalberdStrike CLI 入口"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

# 将项目根目录加入 sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.tree import Tree

console = Console()
logger = None


def _get_orchestrator_class():
    from src.core.orchestrator import Orchestrator
    return Orchestrator


def _get_logger():
    global logger
    if logger is None:
        from src.utils.logger import get_logger
        logger = get_logger("halberdstrike")
    return logger

BANNER = r"""
  _    _       _ _                  _  _____ _        _ _        
 | |  | |     | | |                | |/ ____| |      (_) |       
 | |__| | __ _| | |__   ___ _ __ __| | (___ | |_ _ __ _| | _____ 
 |  __  |/ _` | | '_ \ / _ \ '__/ _` |\___ \| __| '__| | |/ / _ \
 | |  | | (_| | | |_) |  __/ | | (_| |____) | |_| |  | |   <  __/
 |_|  |_|\__,_|_|_.__/ \___|_|  \__,_|_____/ \__|_|  |_|_|\_\___|
                                                                 
  HalberdStrike v1.0
  https://github.com
"""


def _show_disclaimer():
    """显示免责声明"""
    console.print(Panel(
        "[bold red][!] 免责声明[/bold red]\n\n"
        "本工具仅用于[bold]已获授权[/bold]的安全测试。\n"
        "使用者必须确保：\n"
        "  1. 已获得目标系统的合法授权\n"
        "  2. 测试范围已明确定义\n"
        "  3. 理解并接受相关法律责任\n\n"
        "[dim]未经授权的渗透测试是违法行为。[/dim]",
        title="HalberdStrike", border_style="red",
    ))
    if not Confirm.ask("[yellow]是否确认已获得合法授权？[/yellow]"):
        console.print("[red]已取消。[/red]")
        sys.exit(0)


def _create_approval_callback():
    """创建交互式审批回调"""
    def callback(command: str, risk_level: str) -> str:
        console.print(Panel(
            f"[bold yellow][!] 需要人工审批[/bold yellow]\n\n"
            f"[bold]风险等级:[/bold] [red]{risk_level}[/red]\n"
            f"[bold]命令:[/bold]\n  [cyan]{command}[/cyan]",
            border_style="yellow",
        ))
        choice = Prompt.ask(
            "操作",
            choices=["approve", "reject", "modify"],
            default="approve",
        )
        if choice == "approve":
            return "approve"
        elif choice == "reject":
            return "reject"
        else:
            new_cmd = Prompt.ask("[cyan]请输入修改后的命令[/cyan]")
            return f"modify:{new_cmd}"
    return callback


@click.group()
def cli():
    """HalberdStrike - LLM驱动的自动化渗透测试系统"""
    pass


@cli.command()
@click.option("--name", "-n", prompt="项目名称", help="渗透测试项目名称")
@click.option("--target", "-t", prompt="目标地址", help="目标IP/域名/URL")
@click.option("--scope", "-s", multiple=True, help="授权范围（可多次指定）")
@click.option("--config", "-c", default=None, help="配置文件路径")
@click.option("--max-iterations", "-m", default=50, help="最大迭代次数")
@click.option("--web", is_flag=True, default=False, help="启动 Web 仪表盘")
@click.option("--web-port", default=5000, help="Web 仪表盘端口 (默认 5000)")
def start(name: str, target: str, scope: tuple, config: str, max_iterations: int,
          web: bool, web_port: int):
    """创建新项目并启动渗透测试"""
    console.print(BANNER, style="bold green")
    _show_disclaimer()

    scope_list = list(scope) if scope else [target]
    console.print(f"\n[bold]项目:[/bold] {name}")
    console.print(f"[bold]目标:[/bold] {target}")
    console.print(f"[bold]范围:[/bold] {', '.join(scope_list)}")
    console.print(f"[bold]最大迭代:[/bold] {max_iterations}\n")

    orch = _get_orchestrator_class()(config_path=config)
    orch.set_approval_callback(_create_approval_callback())

    web_dashboard = None
    if web:
        web_dashboard = _start_web_dashboard(orch, web_port)

    try:
        project = orch.create_project(name, target, scope_list)
        console.print(f"[green][OK] 项目已创建: {project.id}[/green]\n")

        console.print("[bold]初始PTT:[/bold]")
        console.print(orch.get_tree_display())
        console.print()

        orch.run(max_iterations=max_iterations)

    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断，正在保存状态...[/yellow]")
    except Exception as e:
        console.print(f"\n[red]错误: {e}[/red]")
        _get_logger().error(f"执行异常: {e}", exc_info=True)
    finally:
        if web_dashboard:
            web_dashboard.stop()
        orch.cleanup()
        console.print("[green]状态已保存，可使用 resume 命令恢复。[/green]")


@cli.command()
@click.option("--project-id", "-p", prompt="项目ID", help="要恢复的项目ID")
@click.option("--config", "-c", default=None, help="配置文件路径")
@click.option("--max-iterations", "-m", default=50, help="最大迭代次数")
@click.option("--web", is_flag=True, default=False, help="启动 Web 仪表盘")
@click.option("--web-port", default=5000, help="Web 仪表盘端口 (默认 5000)")
def resume(project_id: str, config: str, max_iterations: int,
           web: bool, web_port: int):
    """恢复已有项目的渗透测试"""
    console.print(BANNER, style="bold green")

    orch = _get_orchestrator_class()(config_path=config)
    orch.set_approval_callback(_create_approval_callback())

    web_dashboard = None
    if web:
        web_dashboard = _start_web_dashboard(orch, web_port)

    try:
        project = orch.load_project(project_id)
        if not project:
            console.print(f"[red]项目不存在: {project_id}[/red]")
            return

        console.print(f"[green][OK] 项目已加载: {project.name} -> {project.target}[/green]\n")
        console.print("[bold]当前PTT:[/bold]")
        console.print(orch.get_tree_display())
        console.print()

        orch.run(max_iterations=max_iterations)

    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断，正在保存状态...[/yellow]")
    except Exception as e:
        console.print(f"\n[red]错误: {e}[/red]")
    finally:
        if web_dashboard:
            web_dashboard.stop()
        orch.cleanup()


@cli.command()
@click.option("--config", "-c", default=None, help="配置文件路径")
def projects(config: str):
    """列出所有项目"""
    orch = _get_orchestrator_class()(config_path=config)
    try:
        all_projects = orch.db.list_projects()
        if not all_projects:
            console.print("[dim]暂无项目[/dim]")
            return

        table = Table(title="渗透测试项目列表")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("名称", style="bold")
        table.add_column("目标", style="green")
        table.add_column("状态")
        table.add_column("创建时间")

        for p in all_projects:
            status_style = {
                "active": "yellow", "paused": "red", "completed": "green"
            }.get(p.status.value, "dim")
            table.add_row(
                p.id[:8] + "...",
                p.name,
                p.target,
                f"[{status_style}]{p.status.value}[/{status_style}]",
                str(p.created_at)[:19],
            )

        console.print(table)
    finally:
        orch.cleanup()


@cli.command()
@click.option("--project-id", "-p", prompt="项目ID", help="项目ID")
@click.option("--config", "-c", default=None, help="配置文件路径")
def tree(project_id: str, config: str):
    """查看项目的PTT状态"""
    orch = _get_orchestrator_class()(config_path=config)
    try:
        project = orch.load_project(project_id)
        if not project:
            console.print(f"[red]项目不存在: {project_id}[/red]")
            return
        console.print(f"\n[bold]{project.name}[/bold] - PTT状态:\n")
        console.print(orch.get_tree_display())
    finally:
        orch.cleanup()


@cli.command()
@click.option("--project-id", "-p", prompt="项目ID", help="项目ID")
@click.option("--config", "-c", default=None, help="配置文件路径")
def report(project_id: str, config: str):
    """为项目生成渗透测试报告"""
    from src.reporting.generator import ReportGenerator

    orch = _get_orchestrator_class()(config_path=config)
    try:
        project = orch.load_project(project_id)
        if not project:
            console.print(f"[red]项目不存在: {project_id}[/red]")
            return

        findings = orch.db.get_findings(project_id)
        action_logs = orch.db.get_action_logs(project_id, limit=200)

        generator = ReportGenerator(orch.provider, orch.file_store)
        report_path = generator.generate(
            project=project,
            tree=orch.reasoning.tree if orch.reasoning else None,
            findings=findings,
            action_logs=action_logs,
        )
        console.print(f"[green][OK] 报告已生成: {report_path}[/green]")
    finally:
        orch.cleanup()


@cli.command()
@click.option("--project-id", "-p", prompt="项目ID", help="项目ID")
@click.option("--config", "-c", default=None, help="配置文件路径")
def history(project_id: str, config: str):
    """查看项目的操作历史"""
    orch = _get_orchestrator_class()(config_path=config)
    try:
        logs = orch.db.get_action_logs(project_id, limit=30)
        if not logs:
            console.print("[dim]暂无操作记录[/dim]")
            return

        table = Table(title="操作历史（最近30条）")
        table.add_column("时间", style="dim", width=19)
        table.add_column("模块", width=12)
        table.add_column("类型", width=10)
        table.add_column("命令", max_width=50)
        table.add_column("风险", width=8)
        table.add_column("耗时", width=8)

        for log in logs:
            risk_style = {"low": "green", "medium": "yellow", "high": "red"}.get(
                log.risk_level.value, "dim"
            )
            table.add_row(
                str(log.timestamp)[:19],
                log.module.value,
                log.action_type.value,
                (log.command or "")[:50],
                f"[{risk_style}]{log.risk_level.value}[/{risk_style}]",
                f"{log.duration_seconds:.1f}s",
            )

        console.print(table)
    finally:
        orch.cleanup()


# ── 交互式模式 ──

@cli.command()
@click.option("--config", "-c", default=None, help="配置文件路径")
def interactive(config: str):
    """启动交互式模式"""
    console.print(BANNER, style="bold green")
    _show_disclaimer()

    orch = _get_orchestrator_class()(config_path=config)
    orch.set_approval_callback(_create_approval_callback())

    console.print("\n[bold]交互式模式[/bold] - 输入 [cyan]help[/cyan] 查看可用命令\n")

    try:
        while True:
            try:
                cmd_input = Prompt.ask("[bold green]halberdstrike[/bold green]").strip()
            except EOFError:
                break

            if not cmd_input:
                continue

            parts = cmd_input.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd in ("quit", "exit", "q"):
                break
            elif cmd == "help":
                _show_interactive_help()
            elif cmd == "new":
                _interactive_new_project(orch, args)
            elif cmd == "load":
                _interactive_load_project(orch, args)
            elif cmd == "start":
                _interactive_start(orch, args)
            elif cmd == "pause":
                orch.pause()
            elif cmd == "resume":
                orch.resume()
            elif cmd == "stop":
                orch.stop()
            elif cmd == "tree":
                console.print(orch.get_tree_display())
            elif cmd == "guide":
                if args:
                    orch.guide(args)
                else:
                    guidance = Prompt.ask("[cyan]请输入指导内容[/cyan]")
                    orch.guide(guidance)
            elif cmd == "projects":
                _interactive_list_projects(orch)
            elif cmd == "findings":
                _interactive_show_findings(orch)
            elif cmd == "report":
                _interactive_generate_report(orch)
            else:
                console.print(f"[red]未知命令: {cmd}[/red]，输入 help 查看帮助")

    except KeyboardInterrupt:
        console.print("\n[yellow]退出中...[/yellow]")
    finally:
        orch.cleanup()
        console.print("[green]已退出。[/green]")


def _show_interactive_help():
    table = Table(title="可用命令", show_header=True)
    table.add_column("命令", style="cyan", width=25)
    table.add_column("描述")
    commands = [
        ("new <name> <target>", "创建新项目"),
        ("load <project_id>", "加载已有项目"),
        ("start [max_iterations]", "开始/恢复渗透测试"),
        ("pause", "暂停执行"),
        ("resume", "恢复执行"),
        ("stop", "停止执行"),
        ("tree", "查看PTT任务树"),
        ("guide <内容>", "人工指导"),
        ("projects", "列出所有项目"),
        ("findings", "查看当前项目发现"),
        ("report", "生成渗透测试报告"),
        ("quit / exit", "退出"),
    ]
    for cmd, desc in commands:
        table.add_row(cmd, desc)
    console.print(table)


def _interactive_new_project(orch: Orchestrator, args: str):
    parts = args.split() if args else []
    if len(parts) >= 2:
        name, target = parts[0], parts[1]
        scope = parts[2:] if len(parts) > 2 else [target]
    else:
        name = Prompt.ask("[cyan]项目名称[/cyan]")
        target = Prompt.ask("[cyan]目标地址[/cyan]")
        scope_input = Prompt.ask("[cyan]授权范围（逗号分隔，默认=目标）[/cyan]", default=target)
        scope = [s.strip() for s in scope_input.split(",")]

    project = orch.create_project(name, target, scope)
    console.print(f"[green][OK] 项目已创建: {project.id}[/green]")
    console.print(orch.get_tree_display())


def _interactive_load_project(orch: Orchestrator, args: str):
    project_id = args.strip() if args else Prompt.ask("[cyan]项目ID[/cyan]")
    project = orch.load_project(project_id)
    if project:
        console.print(f"[green][OK] 已加载: {project.name} -> {project.target}[/green]")
        console.print(orch.get_tree_display())
    else:
        console.print("[red]项目不存在[/red]")


def _interactive_start(orch: Orchestrator, args: str):
    max_iter = int(args) if args and args.isdigit() else 50
    if not orch.project:
        console.print("[red]请先创建或加载项目[/red]")
        return
    console.print(f"[bold]开始执行，最大迭代: {max_iter}[/bold]")
    orch.run(max_iterations=max_iter)


def _interactive_list_projects(orch: Orchestrator):
    all_projects = orch.db.list_projects()
    if not all_projects:
        console.print("[dim]暂无项目[/dim]")
        return
    table = Table(title="项目列表")
    table.add_column("ID", style="cyan")
    table.add_column("名称")
    table.add_column("目标")
    table.add_column("状态")
    for p in all_projects:
        table.add_row(p.id[:12], p.name, p.target, p.status.value)
    console.print(table)


def _interactive_show_findings(orch: Orchestrator):
    if not orch.project:
        console.print("[red]请先加载项目[/red]")
        return
    findings = orch.db.get_findings(orch.project.id)
    if not findings:
        console.print("[dim]暂无发现[/dim]")
        return
    table = Table(title=f"发现列表 ({orch.project.name})")
    table.add_column("严重级别", width=10)
    table.add_column("类型", width=10)
    table.add_column("标题")
    for f in findings:
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow",
                     "low": "blue", "info": "dim"}.get(f.severity.value, "dim")
        table.add_row(
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f.type.value,
            f.title[:60],
        )
    console.print(table)


def _interactive_generate_report(orch: Orchestrator):
    if not orch.project:
        console.print("[red]请先加载项目[/red]")
        return
    from src.reporting.generator import ReportGenerator
    findings = orch.db.get_findings(orch.project.id)
    logs = orch.db.get_action_logs(orch.project.id, limit=200)
    gen = ReportGenerator(orch.provider, orch.file_store)
    path = gen.generate(
        project=orch.project,
        tree=orch.reasoning.tree if orch.reasoning else None,
        findings=findings,
        action_logs=logs,
    )
    console.print(f"[green][OK] 报告已生成: {path}[/green]")


@cli.command()
@click.option("--port", "-p", default=5000, help="Web 仪表盘端口 (默认 5000)")
@click.option("--host", "-H", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
@click.option("--config", "-c", default=None, help="配置文件路径")
def web(port: int, host: str, config: str):
    """启动独立 Web 仪表盘（支持项目管理与扫描控制）"""
    console.print(BANNER, style="bold green")
    console.print(f"\n[bold cyan]启动 Web 仪表盘...[/bold cyan]")
    console.print(f"[dim]地址: http://localhost:{port}[/dim]\n")

    try:
        from src.web.dashboard import WebDashboard
        dashboard = WebDashboard(
            orchestrator=None,
            host=host,
            port=port,
            config_path=config,
        )
        dashboard.start()
        console.print(f"[bold green][OK] Web 仪表盘已启动: http://localhost:{port}[/bold green]")
        console.print("[dim]按 Ctrl+C 停止服务[/dim]\n")

        import time
        while True:
            time.sleep(1)

    except ImportError as e:
        console.print(f"[red]启动失败 (缺少依赖 flask): {e}[/red]")
        console.print("[dim]请运行: pip install flask[/dim]")
    except KeyboardInterrupt:
        console.print("\n[yellow]正在停止 Web 仪表盘...[/yellow]")
        dashboard.stop()
        console.print("[green]已停止。[/green]")
    except Exception as e:
        console.print(f"[red]启动失败: {e}[/red]")
        _get_logger().error(f"Web 启动异常: {e}", exc_info=True)


def _start_web_dashboard(orch, port: int = 5000):
    """启动 Web 仪表盘服务"""
    try:
        from src.web.dashboard import WebDashboard
        dashboard = WebDashboard(orch, host="0.0.0.0", port=port)
        dashboard.start()
        console.print(f"[bold green][OK] Web 仪表盘已启动: http://localhost:{port}[/bold green]")
        return dashboard
    except ImportError as e:
        console.print(f"[red]Web 仪表盘启动失败 (缺少依赖 flask): {e}[/red]")
        console.print("[dim]请运行: pip install flask[/dim]")
        return None
    except Exception as e:
        console.print(f"[red]Web 仪表盘启动失败: {e}[/red]")
        return None


if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]未捕获异常:[/bold red] {e}")
        traceback.print_exc()
        raise SystemExit(1)
