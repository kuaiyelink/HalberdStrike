"""渗透测试任务树 - 树操作"""

from __future__ import annotations

import math
from typing import List, Optional

from src.ptt.node import NodeStatus, PTTNode
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.ptt")


class PTTree:
    """渗透测试任务树管理器"""

    def __init__(self):
        self.root: Optional[PTTNode] = None
        self._node_index: dict[str, PTTNode] = {}

    @staticmethod
    def _detect_target_type(target: str) -> str:
        """检测目标类型: ip / cidr / domain / url"""
        import re
        import ipaddress
        target_clean = target.strip().rstrip("/")
        if re.match(r"^https?://", target_clean):
            return "url"
        try:
            ipaddress.ip_network(target_clean, strict=False)
            return "cidr" if "/" in target_clean else "ip"
        except ValueError:
            pass
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", target_clean):
            return "domain"
        return "ip"

    def init_tree(self, target: str) -> PTTNode:
        """根据目标类型动态初始化PTT"""
        target_type = self._detect_target_type(target)
        logger.info(f"目标类型检测: {target} -> {target_type}")

        self.root = PTTNode(
            name=f"渗透测试 - {target}",
            description=f"对 {target} 进行全面渗透测试 (类型: {target_type})",
            priority=1.0,
        )
        self._node_index[self.root.id] = self.root

        # 通用五阶段
        phases = [
            ("信息收集", "对目标进行全面的信息收集和端口扫描", 0.9),
            ("漏洞扫描", "基于信息收集结果进行漏洞扫描和识别", 0.7),
            ("漏洞利用", "尝试利用已发现的漏洞获取访问权限", 0.5),
            ("后渗透", "在获取权限后进行提权和横向移动", 0.3),
            ("报告生成", "汇总所有发现并生成渗透测试报告", 0.1),
        ]
        phase_nodes = []
        for name, desc, pri in phases:
            node = PTTNode(name=name, description=desc, priority=pri)
            self.root.add_child(node)
            self._node_index[node.id] = node
            phase_nodes.append(node)

        recon, vuln_scan, exploit, post_exploit, report = phase_nodes

        # 设置阶段间依赖
        vuln_scan.depends_on = [recon.id]
        exploit.depends_on = [vuln_scan.id]
        post_exploit.depends_on = [exploit.id]
        report.depends_on = [recon.id]  # 报告只需信息收集完成即可开始

        # 根据目标类型生成不同的初始子任务
        if target_type == "url":
            self._init_url_tasks(recon, vuln_scan, target)
        elif target_type == "domain":
            self._init_domain_tasks(recon, vuln_scan, target)
        elif target_type == "cidr":
            self._init_cidr_tasks(recon, vuln_scan, target)
        else:  # ip
            self._init_ip_tasks(recon, vuln_scan, target)

        logger.info(f"PTT已初始化, 目标: {target}, 类型: {target_type}, "
                    f"节点数: {len(self._node_index)}")
        return self.root

    def _add_sub(self, parent: PTTNode, name: str, desc: str,
                 priority: float, depends: Optional[List[str]] = None) -> PTTNode:
        """添加子任务的辅助方法"""
        node = PTTNode(name=name, description=desc, priority=priority,
                       depends_on=depends or [])
        parent.add_child(node)
        self._node_index[node.id] = node
        return node

    def _init_ip_tasks(self, recon: PTTNode, vuln_scan: PTTNode, target: str):
        """IP 目标的初始任务"""
        tcp = self._add_sub(recon, "TCP全端口扫描",
                            f"nmap -sS -p- --min-rate 1000 {target}", 0.95)
        svc = self._add_sub(recon, "服务版本识别",
                            f"对开放端口进行服务版本和脚本扫描 -sV -sC", 0.9,
                            depends=[tcp.id])
        udp = self._add_sub(recon, "UDP常用端口扫描",
                            f"nmap -sU --top-ports 100 {target}", 0.6)
        self._add_sub(vuln_scan, "Nmap脚本漏洞扫描",
                      "使用nmap vuln脚本对已知服务扫描", 0.8, depends=[svc.id])
        self._add_sub(vuln_scan, "Searchsploit查询",
                      "根据服务版本查询已知漏洞利用", 0.75, depends=[svc.id])

    def _init_domain_tasks(self, recon: PTTNode, vuln_scan: PTTNode, target: str):
        """域名目标的初始任务"""
        dns = self._add_sub(
            recon,
            "DNS枚举",
            f"子域爆破: gobuster dns -d {target} -w 子域名字典(SecLists/DNS 或 amass)，勿用 dirb/common.txt",
            0.95,
        )
        tcp = self._add_sub(recon, "TCP全端口扫描",
                            f"nmap -sS -p- --min-rate 1000 {target}", 0.93)
        svc = self._add_sub(recon, "服务版本识别",
                            f"对开放端口进行服务版本和脚本扫描", 0.9,
                            depends=[tcp.id])
        web = self._add_sub(recon, "Web技术栈探测",
                            f"识别Web服务器、框架、CMS类型", 0.88,
                            depends=[tcp.id])
        self._add_sub(recon, "SSL/TLS检查",
                      f"检查SSL证书和TLS配置", 0.5, depends=[tcp.id])
        self._add_sub(vuln_scan, "Web目录枚举",
                      f"使用gobuster/ffuf枚举Web目录和文件", 0.85,
                      depends=[web.id])
        self._add_sub(vuln_scan, "Nikto Web扫描",
                      f"使用nikto进行Web漏洞扫描", 0.8, depends=[web.id])
        self._add_sub(vuln_scan, "Searchsploit查询",
                      "根据服务版本查询已知漏洞利用", 0.75, depends=[svc.id])

    def _init_url_tasks(self, recon: PTTNode, vuln_scan: PTTNode, target: str):
        """URL 目标的初始任务（Web应用为主）"""
        import re
        host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        tcp = self._add_sub(recon, "端口扫描",
                            f"nmap -sS -p- --min-rate 1000 {host}", 0.9)
        svc = self._add_sub(recon, "服务版本识别",
                            f"对开放端口进行服务版本识别", 0.88,
                            depends=[tcp.id])
        web = self._add_sub(recon, "Web技术栈指纹",
                            f"探测Web框架/CMS/中间件: {target}", 0.95)
        resp = self._add_sub(recon, "HTTP响应分析",
                             f"分析HTTP头、Cookie、安全策略", 0.85)
        self._add_sub(vuln_scan, "Web目录枚举",
                      f"gobuster/ffuf枚举隐藏路径和文件", 0.9,
                      depends=[web.id])
        self._add_sub(vuln_scan, "SQL注入检测",
                      f"使用sqlmap检测注入点: {target}", 0.85,
                      depends=[resp.id])
        self._add_sub(vuln_scan, "XSS/CSRF检测",
                      f"检测跨站脚本和请求伪造漏洞", 0.7,
                      depends=[resp.id])
        self._add_sub(vuln_scan, "Nikto Web扫描",
                      f"nikto全面Web漏洞扫描", 0.8, depends=[web.id])
        self._add_sub(vuln_scan, "认证测试",
                      f"测试默认凭据、暴力破解登录", 0.65,
                      depends=[web.id])

    def _init_cidr_tasks(self, recon: PTTNode, vuln_scan: PTTNode, target: str):
        """CIDR 网段目标的初始任务"""
        alive = self._add_sub(recon, "主机存活探测",
                              f"nmap -sn {target} 发现存活主机", 0.98)
        tcp = self._add_sub(recon, "存活主机端口扫描",
                            f"对存活主机进行TCP常用端口扫描", 0.93,
                            depends=[alive.id])
        svc = self._add_sub(recon, "服务版本识别",
                            f"对开放端口进行服务版本识别", 0.9,
                            depends=[tcp.id])
        self._add_sub(recon, "SMB/NetBIOS枚举",
                      f"enum4linux扫描内网共享和用户", 0.7,
                      depends=[alive.id])
        self._add_sub(vuln_scan, "批量漏洞扫描",
                      "对已识别服务进行漏洞扫描", 0.8, depends=[svc.id])
        self._add_sub(vuln_scan, "弱口令检测",
                      "检测常见服务的弱口令", 0.75, depends=[svc.id])

    def get_node(self, node_id: str) -> Optional[PTTNode]:
        """根据ID获取节点"""
        return self._node_index.get(node_id)

    def update_node(self, node_id: str, status: NodeStatus,
                    findings: Optional[List[str]] = None) -> bool:
        """更新节点状态和发现"""
        node = self._node_index.get(node_id)
        if not node:
            logger.warning(f"节点不存在: {node_id}")
            return False

        node.status = status
        if findings:
            node.findings.extend(findings)
        from datetime import datetime
        node.updated_at = datetime.now()

        logger.info(f"节点已更新: [{node_id}] {node.name} -> {status.value}")
        return True

    def expand_node(self, node_id: str, subtasks: List[dict]) -> List[PTTNode]:
        """展开节点为多个子任务

        subtasks: [{"name": ..., "description": ..., "priority": ...}, ...]
        """
        parent = self._node_index.get(node_id)
        if not parent:
            logger.warning(f"节点不存在: {node_id}")
            return []

        new_nodes = []
        for task in subtasks:
            child = PTTNode(
                name=task.get("name", "未命名任务"),
                description=task.get("description", ""),
                priority=task.get("priority", 0.5),
            )
            parent.add_child(child)
            self._node_index[child.id] = child
            new_nodes.append(child)

        logger.info(f"节点 [{node_id}] 展开为 {len(new_nodes)} 个子任务")
        return new_nodes

    def select_next_task(self) -> Optional[PTTNode]:
        """选择下一个最优执行的叶节点

        策略 (UCB1 + 依赖):
        1. 收集所有 pending 叶节点
        2. 过滤掉依赖未满足的节点
        3. 用 UCB1 公式平衡 探索(未尝试的任务) vs 利用(高奖励任务)
           score = (reward/attempts) + C * sqrt(ln(total)/attempts)
           其中 priority 作为先验加权
        """
        if not self.root:
            return None

        candidates: List[PTTNode] = []
        self._collect_pending_leaves(self.root, candidates)

        # 过滤依赖未满足的节点
        ready = [n for n in candidates if self._deps_satisfied(n)]
        if not ready:
            # 如果所有 pending 都被依赖阻塞，放宽条件选一个尝试次数最少的
            ready = candidates if candidates else []

        if not ready:
            return None

        # UCB1 选择
        total_attempts = sum(n.attempt_count for n in ready) + 1
        C = 1.414  # 探索系数

        def ucb_score(node: PTTNode) -> float:
            if node.attempt_count == 0:
                # 未尝试过的任务给高探索分，加上 priority 先验
                return node.priority * 10.0 + C * 5.0
            exploitation = node.reward / node.attempt_count
            exploration = C * math.sqrt(math.log(total_attempts) / node.attempt_count)
            return exploitation + exploration + node.priority

        ready.sort(key=ucb_score, reverse=True)
        selected = ready[0]
        selected.attempt_count += 1
        return selected

    def _deps_satisfied(self, node: PTTNode) -> bool:
        """检查节点的所有依赖是否已完成"""
        if not node.depends_on:
            return True
        for dep_id in node.depends_on:
            dep_node = self._node_index.get(dep_id)
            if not dep_node:
                continue  # 依赖节点不存在，视为满足
            if dep_node.status not in (NodeStatus.COMPLETED, NodeStatus.SKIPPED):
                return False
        return True

    def _collect_pending_leaves(self, node: PTTNode, result: List[PTTNode]):
        """递归收集所有 pending 的叶节点；同时回收卡在 IN_PROGRESS 的僵死节点"""
        if node.is_leaf():
            if node.status == NodeStatus.PENDING:
                result.append(node)
            elif node.status == NodeStatus.IN_PROGRESS:
                # 僵死回收：节点已被标记 IN_PROGRESS 但未完成，重置为 PENDING 使其可被重选
                logger.debug(f"回收僵死节点: [{node.id}] {node.name}")
                node.status = NodeStatus.PENDING
                result.append(node)
            return

        for child in node.children:
            self._collect_pending_leaves(child, result)

    def update_reward(self, node_id: str, reward_delta: float):
        """更新节点的奖励值（用于 UCB 策略反馈）"""
        node = self._node_index.get(node_id)
        if node:
            node.reward += reward_delta

    def get_tree_summary(self) -> str:
        """生成PTT状态摘要（供LLM推理使用）"""
        if not self.root:
            return "PTT未初始化"
        return self.root.to_summary()

    def get_display_tree(self) -> str:
        """生成PTT可视化字符串（供用户查看）"""
        if not self.root:
            return "PTT未初始化"
        return self.root.to_display_str()

    def get_all_findings(self) -> List[str]:
        """汇总所有节点的发现"""
        findings = []
        for node in self._node_index.values():
            for f in node.findings:
                findings.append(f"[{node.name}] {f}")
        return findings

    def is_completed(self) -> bool:
        """检查是否所有叶节点都已完成/失败/跳过"""
        if not self.root:
            return False
        for node in self._node_index.values():
            if node.is_leaf() and node.status == NodeStatus.PENDING:
                return False
            if node.is_leaf() and node.status == NodeStatus.IN_PROGRESS:
                return False
        return True

    def to_dict(self) -> dict:
        """序列化为字典"""
        if not self.root:
            return {}
        return self.root.model_dump(mode="json")

    def from_dict(self, data: dict):
        """从字典反序列化"""
        if not data:
            return
        self.root = PTTNode.model_validate(data)
        self._node_index.clear()
        self._rebuild_index(self.root)

    def _rebuild_index(self, node: PTTNode):
        """重建节点索引"""
        self._node_index[node.id] = node
        for child in node.children:
            child.parent_id = node.id
            self._rebuild_index(child)
