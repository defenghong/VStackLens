"""Customer health labels are independent of remediation priority levels."""


def assess_health(risk, status, asset_total, critical_unavailable=None, health_impact=None):
    """Assess environment health from operational impact, not P1/P2/P3 alone.

    ``health_impact`` is optional for old report payloads. New contexts pass a
    mapping with ``none``, ``attention`` and ``critical`` counts. When omitted,
    the legacy risk-based behavior is retained for old callers only.
    """
    critical = int(risk.get("P1", 0) or 0)
    important = int(risk.get("P2", 0) or 0)
    general = int(risk.get("P3", 0) or 0)
    unavailable = sum(int(status.get(k, 0) or 0) for k in ("unavailable", "error"))
    evaluated = sum(int(status.get(k, 0) or 0) for k in ("passed", "failed"))
    limited = (unavailable > 0 if critical_unavailable is None else critical_unavailable > 0) or not asset_total or evaluated == 0
    if health_impact is None:
        label = "危险" if critical else "关注" if important else "正常" if general else "健康"
    else:
        critical_impact = int(health_impact.get("critical", 0) or 0)
        attention_impact = int(health_impact.get("attention", 0) or 0)
        label = "危险" if critical_impact else "关注" if attention_impact else "正常" if (critical or important or general) else "健康"
    if limited and label == "健康":
        label = "评估受限"
    explanation = {"危险": "发现需优先处置的严重风险，请查看具体对象及证据。", "关注": "存在需安排处理的重要问题，请按影响范围复核。", "正常": "存在一般问题，建议纳入常规维护。", "健康": "本次必要检查未发现需处理的运行风险。", "评估受限": "当前证据不足以形成完整健康结论，请先复核关键检查覆盖情况。"}[label]
    if limited and label != "评估受限":
        explanation += " 部分检查尚未完成，以上状态仅依据已确认问题。"
    return {"label": label, "assessment_limited": limited, "explanation": explanation}