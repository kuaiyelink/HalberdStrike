"""Gobuster 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


# 目录爆破默认字典；DNS 子域枚举勿用 dirb（多为 /path 片段，会导致 gobuster dns 立即报错）
_DEFAULT_DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_DEFAULT_DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


class GobusterAdapter(ToolAdapter):
    name = "gobuster"
    description = "Web目录和文件枚举工具，支持目录模式(dir)、DNS模式(dns)、虚拟主机模式(vhost)"
    risk_level = "low"
    default_timeout = 300

    def build_command(self, params: Dict[str, Any]) -> str:
        target = params.get("target", "")
        mode = str(params.get("mode", "dir") or "dir").lower().strip()
        threads = int(params.get("threads", 50) or 50)
        extensions = params.get("extensions", "")
        output_file = params.get("output_file", "")

        wl_param = params.get("wordlist")
        if mode == "dns":
            wordlist = (wl_param or "").strip() or _DEFAULT_DNS_WORDLIST
            cmd = f"gobuster dns -d {target} -w {wordlist} -t {threads}"
        elif mode == "vhost":
            wordlist = (wl_param or "").strip() or _DEFAULT_DIR_WORDLIST
            cmd = f"gobuster vhost -u {target} -w {wordlist} -t {threads}"
        else:
            wordlist = (wl_param or "").strip() or _DEFAULT_DIR_WORDLIST
            cmd = f"gobuster dir -u {target} -w {wordlist} -t {threads}"
            if extensions:
                cmd += f" -x {extensions}"

        if output_file:
            cmd += f" -o {output_file}"

        cmd += " --no-error"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "found_paths": [],
            "status_codes": {},
            "summary": "",
        }

        seen_paths = set()

        alt_pattern = re.compile(r"^(/\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", re.MULTILINE)
        for match in alt_pattern.finditer(raw):
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))
            if path not in seen_paths:
                seen_paths.add(path)
                result["found_paths"].append({"path": path, "status": status, "size": size})
                result["status_codes"].setdefault(status, []).append(path)

        path_pattern = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)")
        for match in path_pattern.finditer(raw):
            path = match.group(1)
            status = int(match.group(2))
            if path not in seen_paths:
                seen_paths.add(path)
                result["found_paths"].append({"path": path, "status": status})
                result["status_codes"].setdefault(status, []).append(path)

        # gobuster dns 输出: Found: sub.example.com 或 [+] Found: host
        dns_pattern = re.compile(
            r"(?:^|\n)(?:\[\+\]\s*)?Found:\s*(\S+)",
            re.MULTILINE,
        )
        for match in dns_pattern.finditer(raw):
            host = match.group(1).strip()
            if not host or "/" in host:
                continue
            if host not in seen_paths:
                seen_paths.add(host)
                result["found_paths"].append({"path": host, "status": "dns"})

        n = len(result["found_paths"])
        dns_n = sum(1 for x in result["found_paths"] if x.get("status") == "dns")
        dir_n = n - dns_n
        if dns_n and not dir_n:
            result["summary"] = f"DNS 枚举发现 {dns_n} 个子域/主机名"
        elif dir_n:
            result["summary"] = f"发现 {dir_n} 个路径/文件"
            if result["status_codes"].get(200):
                result["summary"] += f", 其中 {len(result['status_codes'][200])} 个返回200"
            if dns_n:
                result["summary"] += f"；DNS {dns_n} 条"
        else:
            result["summary"] = "未发现路径或子域名"

        return result

    def get_prompt_hint(self) -> str:
        return f"""工具: gobuster
描述: Web 目录爆破与子域名 DNS 爆破（子命令 dir / dns / vhost 参数不同，勿混用）
常用命令:
  - 目录扫描: gobuster dir -u http://<target> -w {_DEFAULT_DIR_WORDLIST} -t 50
  - 带扩展名: gobuster dir -u http://<target> -w <wordlist> -x php,txt,bak,conf
  - DNS 子域名: gobuster dns -d <纯域名无协议> -w <子域名字典> -t 20
重要: DNS 模式必须用 -d 域名、-w 子域名字典；禁止使用 dirb/common.txt（多为 /admin 等路径，会导致 gobuster dns 秒退失败）。
推荐子域名字典(Kali): {_DEFAULT_DNS_WORDLIST}
备选: /usr/share/wordlists/amass/subdomains-top1mil-5000.txt （可 apt install seclists）
  - 虚拟主机: gobuster vhost -u http://<target> -w {_DEFAULT_DIR_WORDLIST} -t 20
风险等级: low"""
