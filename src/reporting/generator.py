"""渗透测试报告生成器 - 支持 Markdown / HTML / PDF 格式"""

from __future__ import annotations

import html as html_lib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.llm.base import LLMProvider
from src.models.action_log import ActionLog
from src.models.finding import Finding, Severity
from src.models.project import Project
from src.ptt.tree import PTTree
from src.storage.file_store import FileStore
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.reporting")

PROMPTS_DIR = Path(__file__).parent.parent.parent / "config" / "prompts"


class ReportGenerator:
    """渗透测试报告生成器"""

    def __init__(self, provider: LLMProvider, file_store: FileStore):
        self.provider = provider
        self.file_store = file_store
        self._prompt_template = self._load_prompt()

    def _load_prompt(self) -> str:
        path = PROMPTS_DIR / "report_template.txt"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    def generate(self, project: Project, tree: Optional[PTTree],
                 findings: List[Finding],
                 action_logs: List[ActionLog],
                 fmt: str = "md") -> str:
        """生成完整渗透测试报告

        Args:
            fmt: 输出格式 'md' / 'html' / 'pdf'
        Returns: 报告文件路径
        """
        logger.info(f"开始生成报告: {project.name} (格式: {fmt})")

        severity_stats = self._count_severity(findings)
        findings_text = self._format_findings(findings)
        attack_path = self._build_attack_path(tree, findings)
        commands_summary = self._summarize_commands(action_logs)

        if self._prompt_template:
            prompt = (
                self._prompt_template
                .replace("{target}", project.target)
                .replace("{scope}", ", ".join(project.scope))
                .replace("{start_time}", str(project.created_at)[:19])
                .replace("{end_time}", str(datetime.now())[:19])
                .replace("{findings}", findings_text)
                .replace("{attack_path}", attack_path)
            )
            messages = [
                {"role": "system", "content": "你是一位专业的渗透测试报告撰写专家。"},
                {"role": "user", "content": prompt},
            ]
            try:
                report_content = self.provider.chat(messages, max_tokens=8192)
            except Exception as e:
                logger.error(f"LLM生成报告失败: {e}，使用模板生成")
                report_content = self._generate_template_report(
                    project, severity_stats, findings, attack_path, commands_summary
                )
        else:
            report_content = self._generate_template_report(
                project, severity_stats, findings, attack_path, commands_summary
            )

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        paths = []

        # 始终保存 Markdown 版本
        md_filename = f"report_{project.name}_{ts}.md"
        md_path = self.file_store.save_report(project.id, md_filename, report_content)
        paths.append(md_path)

        if fmt in ("html", "pdf"):
            html_content = self._md_to_html(report_content, project, severity_stats)
            html_filename = f"report_{project.name}_{ts}.html"
            html_path = self.file_store.save_report(project.id, html_filename, html_content)
            paths.append(html_path)
            logger.info(f"HTML报告已生成: {html_path}")

        if fmt == "pdf":
            pdf_path = self._html_to_pdf(html_path, project.id, ts)
            if pdf_path:
                paths.append(pdf_path)

        primary = paths[-1]
        logger.info(f"报告已生成: {primary}")
        return primary

    def _count_severity(self, findings: List[Finding]) -> Dict[str, int]:
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            stats[f.severity.value] = stats.get(f.severity.value, 0) + 1
        return stats

    def _format_findings(self, findings: List[Finding]) -> str:
        if not findings:
            return "暂无发现"
        lines = []
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                         Severity.LOW, Severity.INFO]
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))
        for f in sorted_findings:
            lines.append(
                f"- [{f.severity.value.upper()}] [{f.type.value}] {f.title}"
            )
            if f.description:
                lines.append(f"  描述: {f.description[:200]}")
            if f.cve_id:
                lines.append(f"  CVE: {f.cve_id}")
            if f.remediation:
                lines.append(f"  修复: {f.remediation[:200]}")
        return "\n".join(lines)

    def _build_attack_path(self, tree: Optional[PTTree],
                           findings: List[Finding]) -> str:
        parts = []
        if tree:
            parts.append("PTT执行路径:\n" + tree.get_tree_summary())
        creds = [f for f in findings if f.type.value == "credential"]
        vulns = [f for f in findings
                 if f.type.value == "vuln" and f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if creds:
            parts.append("发现的凭据:\n" + "\n".join(f"- {c.title}" for c in creds))
        if vulns:
            parts.append("高危漏洞:\n" + "\n".join(f"- {v.title}" for v in vulns))
        return "\n\n".join(parts) if parts else "未建立有效攻击路径"

    def _summarize_commands(self, logs: List[ActionLog]) -> str:
        tool_commands = [l for l in logs if l.command]
        if not tool_commands:
            return "无命令执行记录"
        lines = []
        for log in tool_commands[:30]:
            lines.append(f"- [{str(log.timestamp)[:19]}] {log.command[:80]}")
        return "\n".join(lines)

    def _generate_template_report(self, project: Project,
                                  severity_stats: Dict[str, int],
                                  findings: List[Finding],
                                  attack_path: str,
                                  commands_summary: str) -> str:
        """使用固定模板生成报告（当LLM不可用时）"""
        total = sum(severity_stats.values())
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# 渗透测试报告

## 项目信息

| 项目 | 详情 |
|------|------|
| 项目名称 | {project.name} |
| 目标 | {project.target} |
| 测试范围 | {', '.join(project.scope)} |
| 开始时间 | {str(project.created_at)[:19]} |
| 报告生成时间 | {now} |
| 状态 | {project.status.value} |

## 执行摘要

本次渗透测试共发现 **{total}** 个安全问题：

| 严重级别 | 数量 |
|----------|------|
| 严重 (Critical) | {severity_stats['critical']} |
| 高危 (High) | {severity_stats['high']} |
| 中危 (Medium) | {severity_stats['medium']} |
| 低危 (Low) | {severity_stats['low']} |
| 信息 (Info) | {severity_stats['info']} |

## 详细发现

"""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                         Severity.LOW, Severity.INFO]
        sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

        for i, f in enumerate(sorted_findings, 1):
            report += f"""### {i}. {f.title}

- **严重级别**: {f.severity.value.upper()}
- **类型**: {f.type.value}
- **描述**: {f.description or 'N/A'}
{f'- **CVE**: {f.cve_id}' if f.cve_id else ''}
{f'- **修复建议**: {f.remediation}' if f.remediation else ''}
- **发现时间**: {str(f.timestamp)[:19]}

---

"""

        report += f"""## 攻击路径

{attack_path}

## 命令执行摘要

{commands_summary}

## 免责声明

本报告仅用于授权的安全评估目的。所有测试均在获得明确授权的前提下进行。
报告中的信息仅供目标系统所有者参考，用于改进安全防护。

---
*报告由 HalberdStrike v1.0 自动生成 - {now}*
"""
        return report

    def _md_to_html(self, md_content: str, project: Project,
                    severity_stats: Dict[str, int]) -> str:
        """将 Markdown 报告转换为独立 HTML 文件（内嵌 CSS）"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        escaped = html_lib.escape(md_content)

        # 简易 Markdown -> HTML 转换（不依赖第三方库）
        import re
        body = escaped
        # 标题
        body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', body, flags=re.MULTILINE)
        body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', body, flags=re.MULTILINE)
        body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', body, flags=re.MULTILINE)
        # 粗体
        body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', body)
        # 表格 (简单行转换)
        lines = body.split('\n')
        in_table = False
        converted = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('|') and stripped.endswith('|'):
                cells = [c.strip() for c in stripped.strip('|').split('|')]
                if all(set(c) <= {'-', ' ', ':'} for c in cells):
                    continue  # 跳过分隔行
                if not in_table:
                    converted.append('<table>')
                    in_table = True
                tag = 'th' if not in_table or converted[-1] == '<table>' else 'td'
                row = ''.join(f'<{tag}>{c}</{tag}>' for c in cells)
                converted.append(f'<tr>{row}</tr>')
            else:
                if in_table:
                    converted.append('</table>')
                    in_table = False
                if stripped.startswith('- '):
                    converted.append(f'<li>{stripped[2:]}</li>')
                elif stripped == '---':
                    converted.append('<hr>')
                elif stripped:
                    converted.append(f'<p>{stripped}</p>')
                else:
                    converted.append('')
        if in_table:
            converted.append('</table>')
        body_html = '\n'.join(converted)

        sev_colors = {
            'critical': '#ff1744', 'high': '#ff6d00',
            'medium': '#ffd600', 'low': '#00e676', 'info': '#448aff',
        }
        chart_items = ''.join(
            f'<div class="sev-bar">'
            f'<span class="sev-label">{k.upper()}</span>'
            f'<div class="sev-fill" style="width:{min(v * 20, 100)}%;'
            f'background:{sev_colors.get(k, "#888")}"></div>'
            f'<span class="sev-count">{v}</span></div>'
            for k, v in severity_stats.items()
        )

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>渗透测试报告 - {html_lib.escape(project.name)}</title>
<style>
  :root {{ --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --border: #30363d; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:var(--bg);
          color:var(--fg); line-height:1.7; padding:2rem; max-width:960px; margin:auto; }}
  h1 {{ color:#58a6ff; border-bottom:2px solid var(--border); padding-bottom:.5rem; margin:1.5rem 0 1rem; }}
  h2 {{ color:#79c0ff; margin:1.5rem 0 .8rem; }}
  h3 {{ color:#d2a8ff; margin:1rem 0 .5rem; }}
  p {{ margin:.4rem 0; }}
  table {{ width:100%; border-collapse:collapse; margin:1rem 0; }}
  th, td {{ border:1px solid var(--border); padding:.5rem .8rem; text-align:left; }}
  th {{ background:#161b22; color:var(--accent); }}
  li {{ margin-left:1.5rem; }}
  hr {{ border:none; border-top:1px solid var(--border); margin:1.5rem 0; }}
  strong {{ color:#f0f6fc; }}
  .sev-bar {{ display:flex; align-items:center; gap:.5rem; margin:.3rem 0; }}
  .sev-label {{ width:80px; font-size:.85rem; text-align:right; }}
  .sev-fill {{ height:18px; border-radius:3px; min-width:4px; transition:width .3s; }}
  .sev-count {{ font-weight:bold; font-size:.9rem; }}
  .header {{ text-align:center; padding:1.5rem; border:1px solid var(--border);
             border-radius:8px; margin-bottom:2rem; background:#161b22; }}
  .footer {{ text-align:center; color:#8b949e; font-size:.85rem; margin-top:2rem; }}
  @media print {{ body {{ background:#fff; color:#000; }}
    th, td {{ border-color:#ccc; }} h1,h2,h3 {{ color:#000; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>PENETRATION TEST REPORT</h1>
  <p>{html_lib.escape(project.name)} &mdash; {html_lib.escape(project.target)}</p>
  <p style="color:#8b949e">{now}</p>
</div>
<h2>Severity Distribution</h2>
{chart_items}
{body_html}
<div class="footer">HalberdStrike v1.0 &mdash; Generated {now}</div>
</body>
</html>"""

    def _html_to_pdf(self, html_path: str, project_id: str, ts: str) -> Optional[str]:
        """尝试将 HTML 转换为 PDF（需要 weasyprint 或 pdfkit）"""
        try:
            import weasyprint
            pdf_filename = f"report_{project_id}_{ts}.pdf"
            pdf_dir = Path(html_path).parent
            pdf_full = pdf_dir / pdf_filename
            weasyprint.HTML(filename=html_path).write_pdf(str(pdf_full))
            logger.info(f"PDF报告已生成: {pdf_full}")
            return str(pdf_full)
        except ImportError:
            pass
        try:
            import pdfkit
            pdf_filename = f"report_{project_id}_{ts}.pdf"
            pdf_dir = Path(html_path).parent
            pdf_full = pdf_dir / pdf_filename
            pdfkit.from_file(html_path, str(pdf_full))
            logger.info(f"PDF报告已生成(pdfkit): {pdf_full}")
            return str(pdf_full)
        except (ImportError, Exception) as e:
            logger.warning(f"PDF生成不可用(安装 weasyprint 或 pdfkit): {e}")
            return None
