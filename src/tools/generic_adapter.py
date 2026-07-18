"""通用命令适配器 - 用于未专门适配的工具"""

from __future__ import annotations

from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class GenericAdapter(ToolAdapter):
    name = "generic"
    description = "通用命令适配器，处理白名单中未专门适配的工具"
    risk_level = "low"
    default_timeout = 120

    def __init__(self, tool_name: str = "generic", risk: str = "low"):
        self.name = tool_name
        self.risk_level = risk

    def build_command(self, params: Dict[str, Any]) -> str:
        return params.get("command", "")

    def parse_output(self, raw: str) -> Dict[str, Any]:
        lines = raw.strip().split("\n")
        return {
            "raw_lines": len(lines),
            "output_preview": "\n".join(lines[:20]),
            "summary": f"命令输出 {len(lines)} 行",
        }

    def get_prompt_hint(self) -> str:
        return f"工具: {self.name}\n描述: 通用命令\n风险等级: {self.risk_level}"


# ── 快捷适配器工厂 ──

TOOL_REGISTRY: Dict[str, ToolAdapter] = {}


def register_all_adapters():
    """注册所有内置工具适配器"""
    from src.tools.nmap_adapter import NmapAdapter
    from src.tools.gobuster_adapter import GobusterAdapter
    from src.tools.nikto_adapter import NiktoAdapter
    from src.tools.sqlmap_adapter import SqlmapAdapter
    from src.tools.hydra_adapter import HydraAdapter
    from src.tools.metasploit_adapter import MetasploitAdapter
    from src.tools.searchsploit_adapter import SearchsploitAdapter

    adapters = [
        NmapAdapter(),
        GobusterAdapter(),
        NiktoAdapter(),
        SqlmapAdapter(),
        HydraAdapter(),
        MetasploitAdapter(),
        SearchsploitAdapter(),
    ]

    for adapter in adapters:
        TOOL_REGISTRY[adapter.name] = adapter

    generic_tools = {
        "enum4linux": ("SMB/NetBIOS枚举工具", "low"),
        "smbclient": ("SMB文件访问客户端", "low"),
        "curl": ("HTTP请求工具", "low"),
        "wget": ("文件下载工具", "low"),
        "ffuf": ("快速Web模糊测试工具", "low"),
        "dirb": ("Web目录扫描工具", "low"),
        "wfuzz": ("Web模糊测试工具", "medium"),
        "john": ("密码哈希破解工具", "medium"),
        "hashcat": ("GPU密码哈希破解工具", "medium"),
        "nc": ("Netcat网络工具", "medium"),
        "ncat": ("Ncat网络工具", "medium"),
        "socat": ("多功能网络工具", "medium"),
    }
    for tool_name, (desc, risk) in generic_tools.items():
        adapter = GenericAdapter(tool_name, risk)
        adapter.description = desc
        TOOL_REGISTRY[tool_name] = adapter

    return TOOL_REGISTRY


def get_adapter(tool_name: str) -> ToolAdapter:
    """获取工具适配器"""
    if not TOOL_REGISTRY:
        register_all_adapters()
    return TOOL_REGISTRY.get(tool_name, GenericAdapter(tool_name))


def get_all_tool_hints() -> str:
    """获取所有工具的prompt提示"""
    if not TOOL_REGISTRY:
        register_all_adapters()
    hints = []
    for name, adapter in sorted(TOOL_REGISTRY.items()):
        hints.append(adapter.get_prompt_hint())
    return "\n\n".join(hints)
