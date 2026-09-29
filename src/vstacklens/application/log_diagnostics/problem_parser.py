from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ProblemContext:
    problem_description: str
    profile: dict[str, Any]
    scenario: str | None


class ProblemParser:
    """Parse the customer question before any diagnosis scenario is selected."""

    OBJECT_PATTERNS = (
        re.compile(r"(?:\d{1,3}\.){3}\d{1,3}"),
        re.compile(r"\bnaa\.[A-Za-z0-9._:-]+\b", re.I),
        re.compile(r"\b(?:vmnic|vmk)\d+\b", re.I),
        re.compile(r"\bdvport\b[\s#:=-]*\d+\b", re.I),
        re.compile(r"\bportgroup\b[\s:_-]*[A-Za-z0-9._-]+\b", re.I),
        re.compile(r"\b[A-Za-z0-9._+-]+\.vmdk\b", re.I),
        re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._-]*[0-9][A-Za-z0-9._-]*\b"),
        re.compile(r"\b[A-Za-z0-9][A-Za-z0-9._-]*[._-][A-Za-z0-9._-]+\b"),
    )
    OBJECT_STOP_WORDS = {
        "the",
        "and",
        "for",
        "after",
        "before",
        "failed",
        "failure",
        "network",
        "storage",
        "snapshot",
        "problem",
        "issue",
        "vmware",
        "vcenter",
        "vsphere",
        "esxi",
        "support",
        "bundle",
        "guest",
        "reconnect",
        "disconnect",
        "migration",
        "migrate",
        "relocate",
        "vmotion",
        "datastore",
        "portgroup",
        "dvport",
        "vlan",
        "uplink",
        "ethernet",
        "timeout",
        "unreachable",
        "connection",
        "connected",
        "descending",
        "degraded",
        "absent",
        "clomd",
        "cmmds",
        "vsan",
        "dom",
    }
    DOMAIN_RULES = (
        ("迁移", ("在线迁移", "迁移", "vmotion", "migrate", "relocate", "migration")),
        ("网络", ("网络", "不通", "断连", "连接", "中断", "network", "dvport", "portgroup", "vlan", "vmnic", "uplink")),
        ("虚拟网卡", ("虚拟网卡", "网卡", "重连", "断开", "ethernet", "vmxnet", "reconnect", "disconnect")),
        ("虚拟机", ("虚拟机", "vm", "开机", "关机", "重启", "power on", "power off", "reset")),
        ("快照", ("快照", "snapshot", "consolidat", "vmdk", "removeallsnapshots")),
        ("存储", ("存储", "datastore", "lun", "naa.", "scsi", "apd", "pdl", "hba")),
        ("vSAN", ("vsan", "clomd", "cmmds", "dom owner", "absent", "degraded")),
        ("认证", ("登录", "认证", "权限", "sso", "sts", "token", "authentication", "permission")),
        ("证书", ("证书", "certificate", "ssl", "tls", "x509")),
        ("服务状态", ("服务", "crash", "panic", "failed to start", "watchdog", "vmon")),
        ("性能", ("慢", "卡顿", "响应慢", "延迟", "latency", "slow", "performance", "timeout")),
    )

    def parse_context(self, problem_description: str) -> ProblemContext:
        profile = self.parse(problem_description)
        return ProblemContext(problem_description=problem_description, profile=profile, scenario=self.detect_scenario(problem_description))

    def detect_scenario(self, problem_description: str) -> str | None:
        text = problem_description.lower()
        snapshot_terms = ("快照", "snapshot", "vmdk", "-00000", "磁盘链", "需要整合")
        action_terms = (
            "整合",
            "合并",
            "删除",
            "失败",
            "卡住",
            "consolidat",
            "removeallsnapshots",
            "needs consolidation",
            "needconsolidate",
        )
        if any(term in text for term in snapshot_terms) and any(term in text for term in action_terms):
            return "snapshot_consolidation_failure"

        migration_terms = ("在线迁移", "迁移", "vmotion", "migrate", "relocate", "migration")
        network_terms = (
            "网络不通",
            "网络异常",
            "不通",
            "断连",
            "虚拟网卡",
            "网卡",
            "重连",
            "disconnect",
            "reconnect",
            "dvport",
            "portgroup",
            "vlan",
        )
        if any(term in text for term in migration_terms) and any(term in text for term in network_terms):
            return "vm_migration_network_loss"
        return None

    def parse(self, problem_description: str) -> dict[str, Any]:
        text = problem_description.strip()
        lower_text = text.lower()
        objects = self._extract_objects(text)

        domains = [label for label, terms in self.DOMAIN_RULES if self._domain_matches(lower_text, terms)]
        if not domains:
            domains = ["未知"]

        action_rules = (
            ("迁移", ("在线迁移", "迁移", "vmotion", "migrate", "relocate")),
            ("重连", ("重连", "重新连接", "reconnect")),
            ("连接", ("连接", "connect", "connected")),
            ("断开", ("断开", "disconnect", "disconnected", "中断")),
            ("开机", ("开机", "power on")),
            ("关机", ("关机", "power off", "shutdown")),
            ("快照合并", ("整合", "合并", "consolidat", "removeallsnapshots")),
            ("登录", ("登录", "login", "authentication")),
        )
        actions = [label for label, terms in action_rules if any(term in lower_text for term in terms)]

        symptom_rules = (
            ("网络不通", ("网络不通", "不通", "unreachable", "no route")),
            ("网络异常", ("网络异常", "断连", "network", "link down", "dropped")),
            ("业务中断", ("业务异常", "中断", "interrupted", "disconnect")),
            ("失败", ("失败", "failed", "failure", "error")),
            ("超时", ("超时", "timeout", "timed out")),
            ("卡住", ("卡住", "hang", "stuck", "no taskinfo")),
            ("慢", ("慢", "latency", "slow")),
            ("无法访问", ("无法访问", "cannot access", "inaccessible")),
        )
        symptoms = [label for label, terms in symptom_rules if any(term in lower_text for term in terms)]

        time_patterns = (
            r"\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}(?::\d{2})?",
            r"\d{1,2}:\d{2}(?::\d{2})?",
            r"\d{1,2}月\d{1,2}日",
            r"(?:今天|昨天|前天|上午|下午|晚上|凌晨)",
        )
        times: list[str] = []
        for pattern in time_patterns:
            times.extend(match.group(0) for match in re.finditer(pattern, text))
        times = list(dict.fromkeys(times))

        return {
            "objects": objects,
            "primary_object": objects[0] if objects else "当前问题描述未明确提供",
            "actions": actions,
            "symptoms": symptoms,
            "domains": domains,
            "time_hints": times,
            "time_status": "已提供" if times else "未提供",
        }

    def _extract_objects(self, text: str) -> list[str]:
        candidates: list[tuple[int, str]] = []
        for pattern in self.OBJECT_PATTERNS:
            candidates.extend((match.start(), match.group(0)) for match in pattern.finditer(text))

        candidates.sort(key=lambda item: (item[0], len(item[1])))

        objects: list[str] = []
        seen: set[str] = set()
        for _index, raw in candidates:
            item = raw.strip(".,;:，。；：()[]{}<>\"'")
            if not item:
                continue
            lowered = item.lower()
            if lowered in self.OBJECT_STOP_WORDS:
                continue
            if lowered.startswith("portgroup") and lowered == "portgroup":
                continue
            if lowered.startswith("dvport") and lowered == "dvport":
                continue
            if not self._looks_like_object(item):
                continue
            if lowered in seen:
                continue
            seen.add(lowered)
            objects.append(item)
        return objects

    def _looks_like_object(self, token: str) -> bool:
        lowered = token.lower()
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
            return True
        if lowered.startswith(("naa.", "vmnic", "vmk")):
            return True
        if lowered.endswith(".vmdk"):
            return True
        if lowered.startswith("dvport"):
            return True
        if any(ch.isdigit() for ch in token):
            return True
        return any(ch in token for ch in "._-")

    def _domain_matches(self, lower_text: str, terms: tuple[str, ...]) -> bool:
        for term in terms:
            lowered = term.lower()
            if re.search(r"[\u4e00-\u9fff]", lowered):
                if lowered in lower_text:
                    return True
                continue
            if any(ch in lowered for ch in ".-_/ "):
                if lowered in lower_text:
                    return True
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(lowered)}(?![a-z0-9])", lower_text):
                return True
        return False
