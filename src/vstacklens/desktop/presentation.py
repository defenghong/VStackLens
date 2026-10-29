"""Presentation-only names and Shanghai timestamps; never alter stored data."""
from datetime import datetime, timezone, timedelta
import re

NAMES = {
    "ClusterComputeResource": "集群", "HostSystem": "ESXi 主机",
    "VirtualMachine": "虚拟机", "Datastore": "数据存储", "Cluster": "集群",
    "VM": "虚拟机", "ESXi Host": "ESXi 主机", "ESXi": "ESXi 主机",
    "success": "成功", "failed": "失败", "running": "进行中", "idle": "等待开始",
    "cancelled": "已取消", "canceled": "已取消", "cancel_requested": "正在取消",
    "passed": "通过", "unavailable": "资料不足", "not_applicable": "无需检查",
    "error": "失败", "unknown": "未确认", "open": "待整改", "resolved": "已关闭",
    "exception": "已例外", "reopened": "重新出现", "connected": "已连接",
    "disconnected": "未连接", "notResponding": "无响应", "poweredOn": "运行",
    "poweredOff": "关机", "powered_on": "运行", "powered_off": "关机",
    "suspended": "挂起", "fullyAutomated": "全自动", "partiallyAutomated": "部分自动",
    "manual": "手动", "available": "可用", "enabled": "已启用", "disabled": "未启用",
    "normal": "正常", "healthy": "健康", "warning": "关注", "critical": "严重",
    "collected": "已取得资料", "not_collected": "未取得资料", "unsupported": "暂不支持",
    "queued": "等待执行", "pending": "待处理", "complete": "完成", "completed": "完成",
}
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?")
_NAME = re.compile(r"(?<![\w])(" + "|".join(re.escape(k) for k in sorted(NAMES, key=len, reverse=True)) + r")(?![\w])")
SHANGHAI = timezone(timedelta(hours=8), "Asia/Shanghai")

def local_time(value, *, compact=False):
    if not value:
        return "—"
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.astimezone(SHANGHAI).strftime("%m-%d %H:%M" if compact else "%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return str(value)

def ui_text(value):
    text = str(value or "")
    text = _DATE.sub(lambda m: local_time(m.group()) if "T" in m.group() or len(m.group()) > 16 else m.group(), text)
    return _NAME.sub(lambda m: m.group() if m.group() == "ESXi" and text[m.end():].startswith(" 主机") else NAMES[m.group()], text)

def object_name(value):
    return NAMES.get(str(value), str(value))

def history_change(value):
    return {"new":"新增","closed":"本次未再发现","resolved":"本次未再发现","removed":"本次未再发现","persistent":"持续"}.get(str(value),str(value))

def power_state(value):
    """VM power only; never fall back to a connection state."""
    return {"poweredOn":"运行中","powered_on":"运行中","running":"运行中","poweredOff":"关机","powered_off":"关机","suspended":"挂起"}.get(str(value or ""),"—")

def metadata_text(value):
    if value is None:return "—"
    text=str(value).strip()
    placeholders={"", "未指定站点","未指定客户","未填写客户","未填写站点","未指定环境","未填写环境","未指定项目"}
    return "—" if text in placeholders else text

def task_numbers(db_path):
    """Read-only daily numbering, across all standard tasks, in creation order."""
    import sqlite3
    from pathlib import Path
    path = Path(db_path)
    if not path.is_file(): return {}
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        rows = conn.execute("SELECT run_id, created_at FROM inspection_runs ORDER BY created_at, run_id").fetchall()
    counts, result = {}, {}
    for run_id, stamp in rows:
        day = local_time(stamp).split(" ")[0].replace("-", "")
        if not re.fullmatch(r"\d{8}", day): continue
        counts[day] = counts.get(day, 0) + 1
        result[run_id] = f"S-{day}-{counts[day]:02d}"
    return result

def current_sentence(item):
    """Present supplied evidence; never infer a missing value or a threshold."""
    current, expected = str(item.current_observed or "").strip(), str(item.expected_state or "").strip()
    unknown = {"", "未记录", "—", "None", "按健康评估基线执行"}
    title = ui_text(item.rule_name or item.title)
    if current in unknown:
        return f"{title}：尚无可展示的当前值。"
    if current.lower() in {"true", "false"}:
        current = "已启用" if current.lower() == "true" else "未启用"
    if expected.lower() in {"true", "false"}:
        expected = "启用" if expected.lower() == "true" else "关闭"
    # Units/operators come from the existing structured rule evidence, not new policy.
    evidence = item.raw_evidence or {}
    unit = evidence.get("unit", "")
    if not unit:
        unit = {"VSL-CL-005": "%", "VSL-HOST-005": "%", "VSL-HOST-006": "%", "VSL-DS-001": "%", "VSL-HOST-008": " 天", "VSL-VC-005": " 天", "VSL-HOST-023": " 天"}.get(item.rule_id, "")
    if not unit and "%" in expected and re.fullmatch(r"\d+(?:\.\d+)?", current): unit = "%"
    if unit and re.fullmatch(r"\d+(?:\.\d+)?", current): current += str(unit)
    match = re.fullmatch(r"([<>]=?)\s*(\d+(?:\.\d+)?)", expected)
    if match:
        expected = {"<": "低于", "<=": "不高于", ">": "高于", ">=": "不低于"}[match[1]] + " " + match[2] + str(unit)
    sentence = f"{title} {ui_text(current)}"
    if expected not in unknown: sentence += f"，建议{ui_text(expected)}"
    return sentence.rstrip("。") + "。"
