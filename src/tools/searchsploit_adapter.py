"""SearchSploit 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class SearchsploitAdapter(ToolAdapter):
    name = "searchsploit"
    description = "Exploit-DB本地漏洞搜索工具，根据服务名称和版本搜索已知漏洞利用代码"
    risk_level = "low"
    default_timeout = 60

    def build_command(self, params: Dict[str, Any]) -> str:
        query = params.get("query", "")
        json_output = params.get("json", False)

        cmd = f"searchsploit {query}"
        if json_output:
            cmd += " --json"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "exploits": [],
            "summary": "",
        }

        line_pattern = re.compile(
            r"(.+?)\s+\|\s+(exploits?/\S+|shellcodes?/\S+)"
        )
        for match in line_pattern.finditer(raw):
            title = match.group(1).strip()
            path = match.group(2).strip()
            if title and not title.startswith("---") and "Title" not in title:
                result["exploits"].append({
                    "title": title,
                    "path": path,
                })

        n = len(result["exploits"])
        result["summary"] = f"找到 {n} 个相关漏洞利用"
        if n > 0:
            titles = [e["title"][:50] for e in result["exploits"][:3]]
            result["summary"] += f": {'; '.join(titles)}"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: searchsploit
描述: 本地漏洞利用搜索
常用命令:
  - 搜索: searchsploit <service> <version>
  - 示例: searchsploit apache 2.4.49
  - 查看详情: searchsploit -x <path>
  - 复制到当前目录: searchsploit -m <path>
风险等级: low"""
