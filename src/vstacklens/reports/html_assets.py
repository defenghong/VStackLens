REPORT_JS = r"""
const DATA = JSON.parse(document.getElementById("report-data").textContent);
const ctx = DATA.report_context || {};
const findings = DATA.findings || [];
const riskGroups = DATA.risk_group_summary || [];
const assets = DATA.assets || {};
const tracking = ctx.remediation_tracking || {};
const certificateLicenseEvidence = DATA.certificate_license_evidence || ctx.appendix?.certificate_license_evidence || [];
const historyComparison = ctx.history_comparison || ctx.appendix?.history_comparison || {};
const vsanSummary = ctx.vsan_summary || {};

const objectTypeLabels = {
  vCenter: "vCenter 管理平台",
  ClusterComputeResource: "集群",
  HostSystem: "ESXi 主机",
  Datastore: "数据存储",
  VirtualMachine: "虚拟机",
};
const severityOrder = {P1: 1, P2: 2, P3: 3};

function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function table(headers, rows, className = "") {
  const cls = className ? ` class="${esc(className)}"` : "";
  return `<table${cls}><thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${headers.length}">无数据</td></tr>`}</tbody></table>`;
}

function metric(label, value) {
  const shown = (value === null || value === undefined) ? "" : value;
  return `<div class="card"><div class="label">${esc(label)}</div><div class="value">${esc(shown)}</div></div>`;
}

function riskTotal() {
  const risk = ctx.risk_summary || {};
  return (risk.total === null || risk.total === undefined) ? ((risk.P1 || 0) + (risk.P2 || 0) + (risk.P3 || 0)) : risk.total;
}

function optimizationTotal() {
  const risk = ctx.risk_summary || {};
  return (risk.optimization_total === null || risk.optimization_total === undefined) ? 0 : risk.optimization_total;
}

function highRiskTotal() {
  const risk = ctx.risk_summary || {};
  return (risk.P1 || 0) + (risk.P2 || 0);
}

function focusAreaText() {
  const words = [];
  const text = findings.map(item => `${item.title} ${item.summary}`).join(" ");
  if (/HA|心跳|隔离/.test(text)) words.push("HA");
  if (/网络|链路|上行/.test(text)) words.push("网络链路");
  if (/vMotion/.test(text)) words.push("vMotion");
  if (/快照/.test(text)) words.push("快照");
  if (/SSH|Lockdown|安全/.test(text)) words.push("主机安全配置");
  if (/告警/.test(text)) words.push("活动告警");
  return words.length ? words.slice(0, 5).join("、") : "已发现风险项";
}

function conclusionText() {
  const risk = ctx.risk_summary || {};
  const health = ctx.health_score || {};
  if ((risk.P1 || 0) > 0) {
    return `当前环境健康状态为 ${health.label || "评估受限"}；发现 ${risk.P1} 类 P1 整改优先级问题，建议优先复核 ${focusAreaText()}。`;
  }
  if (riskTotal() === 0) {
    return "当前环境未发现明确风险项，建议保持周期巡检，并在重大变更后复核关键配置。";
  }
  return `当前环境健康状态为 ${health.label || "评估受限"}；存在 P2/P3 整改优先级问题和优化建议，建议优先处理 ${focusAreaText()} 等问题。`;
}

function scoreExplanation() {
  return (ctx.health_score || {}).explanation || "请结合本次检查覆盖范围及问题证据评估。";
}

function priorityText() {
  const risk = ctx.risk_summary || {};
  if ((risk.P1 || 0) > 0) return "优先处理 P1 问题类别";
  if ((risk.P2 || 0) > 0) return "优先处理 P2 问题类别";
  if ((risk.P3 || 0) > 0) return "纳入近期维护计划";
  return "保持周期巡检";
}

function timeRange() {
  const timing = ctx.run_timing || {};
  const start = timing.started_at || ctx.report_info?.generated_at || "";
  const end = timing.finished_at || ctx.report_info?.generated_at || "";
  return start && end ? `${start} ~ ${end}` : start || end || "";
}

function assetInventoryRows() {
  const rows = [];
  for (const [type, items] of Object.entries(assets.details || {})) {
    for (const item of items || []) rows.push({type, ...item});
  }
  return rows;
}

function renderOverview() {
  const ri = ctx.report_info || {};
  const ci = ctx.customer_info || {};
  const env = ctx.environment_summary || {};
  const envInfo = ctx.environment_info || {};
  const hs = ctx.health_score || {};
  const status = ctx.status_summary || {};
  const risk = ctx.risk_summary || {};
  const riskObjects = ctx.risk_object_summary || {};
  const summary = assets.summary || {};
  const verification = ctx.verification_coverage || {};
  const vsan = ctx.vsan_summary || {};
  const vsanApplicable = Boolean(vsan.status && vsan.status !== "not_applicable");
  const diagnostics = envInfo.connection_diagnostics || {};
  const diagnosticRows = ["port", "sdk"]
    .filter(key => diagnostics[key] && diagnostics[key].message)
    .map(key => `<div>${esc({"port": "端口检测", "sdk": "SDK 检测"}[key])}</div><div>${esc(diagnostics[key].message)}</div>`)
    .join("");
  const suggestedActions = (diagnostics.suggested_actions || []).map(item => `<li>${esc(item)}</li>`).join("");
  const modeNotice = (envInfo.data_coverage_summary || diagnosticRows || suggestedActions) ? `
    <div class="mode-notice">
      <strong>${esc(envInfo.collection_mode_label || "采集方式")}</strong>
      ${envInfo.data_coverage_summary ? `<p>${esc(envInfo.data_coverage_summary)}</p>` : ""}
      ${diagnosticRows ? `<div class="kv compact-kv diagnostic-kv">${diagnosticRows}</div>` : ""}
      ${suggestedActions ? `<ul>${suggestedActions}</ul>` : ""}
    </div>` : "";
  document.getElementById("overview").innerHTML = `
    <h2>总览</h2>
    <div class="executive-panel">
      <div>
        <div class="eyebrow">本次巡检结论</div>
        <p class="conclusion">${esc(conclusionText())}</p>
        <p class="score-note">${esc(scoreExplanation(hs.score))}</p>
        <div class="priority-strip"><span>整改优先级</span><strong>${esc(priorityText())}</strong></div>
      </div>
      <div class="score-dial" data-health="${esc(hs.label || "评估受限")}"><span>${esc(hs.label || "评估受限")}</span><small>健康状态</small></div>
    </div>
    <h3>环境规模</h3>
    <div class="grid overview-grid">
       ${metric("整体状态", hs.label || "评估受限")}
       ${metric("风险总数", riskTotal())}
       ${metric("优化建议", optimizationTotal())}
       ${metric("采集对象", (env.covered_object_total === null || env.covered_object_total === undefined) ? ((assets.total === null || assets.total === undefined) ? 0 : assets.total) : env.covered_object_total)}
       ${metric("检查覆盖 / 正常项", `${verification.covered_count || 0} / ${status.passed || 0}`)}
       ${metric("通过对象数", status.passed_objects || status.passed || 0)}
    </div>
    <div class="overview-columns">
      <section>
        <h3>问题摘要</h3>
        <div class="risk-distribution">
          <span class="risk-P1">P1 问题类别 ${risk.P1 || 0}（对象 ${riskObjects.P1 || 0}）</span>
          <span class="risk-P2">P2 问题类别 ${risk.P2 || 0}（对象 ${riskObjects.P2 || 0}）</span>
          <span class="risk-P3">P3 问题类别 ${risk.P3 || 0}（对象 ${riskObjects.P3 || 0}）</span>
          <span class="status-passed">通过检查 ${status.passed || 0}</span>
          <span class="status-failed">未通过检查 ${status.failed || 0}</span>
        </div>
        <div class="note">P1/P2/P3 按问题类别统计（同一 rule_id + risk_level 只计 1 类），括号内为受影响对象明细数；通过/未通过按检查结果统计。</div>
      </section>
      <section>
        <h3>巡检范围</h3>
        <div class="scope-pills">
          <span>vCenter ${summary.vCenter || 0}</span>
          <span>集群 ${summary.ClusterComputeResource || 0}</span>
          <span>ESXi 主机 ${summary.HostSystem || 0}</span>
          <span>数据存储 ${summary.Datastore || 0}</span>
          <span>虚拟机 ${summary.VirtualMachine || 0}</span>
          ${vsanApplicable ? `<span>vSAN 集群 ${(vsan.clusters || []).length || 0}；主机 ${vsan.host_count == null ? "未确认" : vsan.host_count}；容量 ${vsan.capacity?.used_percent == null ? "未确认" : `${vsan.capacity.used_percent}%`}</span>` : ""}
        </div>
      </section>
    </div>
    <h3>资产范围</h3>
    <div class="note">总览只呈现资产数量；完整资产清单请切换到 vCenter 模块查看。</div>
    <h3>巡检任务信息</h3>
    <div class="kv compact-kv">
      <div>报告名称</div><div>${esc(ri.report_title)}</div>
      <div>客户名称</div><div>${esc(ci.customer_name || "未指定客户")}</div>
      <div>vCenter</div><div>${esc(envInfo.vcenter || "未采集")}</div>
      <div>vCenter 版本</div><div>${esc(envInfo.vcenter_version || "未采集")}</div>
      <div>采集方式</div><div>${esc(envInfo.collection_mode_label || "完整 SDK 采集")}</div>
      <div>采集时间</div><div>${esc(timeRange())}</div>
    </div>
    ${modeNotice}`;
}

function signedNumber(value) {
  if (value === null || value === undefined || value === "") return "无对比";
  const number = Number(value);
  if (Number.isNaN(number)) return value;
  return number > 0 ? `+${number}` : `${number}`;
}

function trackingNarrative() {
  const summary = tracking.summary || {};
  if (!tracking.previous_run_id) return "本次报告作为后续整改复核的基线。下一次巡检后，将展示新增风险和本次未再检出风险。";
  if ((summary.new || 0) === 0 && (summary.resolved || 0) === 0) return "本次未发现新增风险，也未发现未再检出风险。";
  if ((summary.new || 0) === 0) return `本次未发现新增风险，本次未再检出 ${summary.resolved || 0} 项风险。`;
  if ((summary.resolved || 0) === 0) return `本次新增 ${summary.new || 0} 项风险，本次未发现未再检出风险。`;
  return `本次新增 ${summary.new || 0} 项风险，本次未再检出 ${summary.resolved || 0} 项风险。`;
}

function trackingRows(items, emptyText) {
  if (!items || !items.length) return `<div class="empty-note">${esc(emptyText)}</div>`;
  return table(["等级", "风险标题", "对象"], items.map(item => `<tr><td class="risk-${esc(item.risk_level)}">${esc(item.risk_level)}</td><td>${esc(item.title)}</td><td>${esc(item.object_name)}</td></tr>`));
}

function renderRemediationTracking() {
  const summary = tracking.summary || {};
  document.getElementById("tracking").innerHTML = `
    <h2>整改跟踪</h2>
    <div class="tracking-summary">
      <div>
        <div class="eyebrow">巡检对比</div>
        <p class="conclusion small">${esc(trackingNarrative())}</p>
      </div>

    </div>
    <div class="grid tracking-grid">
      ${metric("新增风险", summary.new || 0)}
      ${metric("本次未再检出", summary.resolved || 0)}
    </div>
    <div class="tracking-columns">
      <section><h3>新增风险</h3>${trackingRows(tracking.new_findings || [], "本次未发现新增风险。")}</section>
      <section><h3>本次未再检出</h3>${trackingRows(tracking.resolved_findings || [], "本次未发现未再检出风险。")}</section>
    </div>`;
}

function groupedRisks() {
  const grouped = new Map();
  for (const item of findings) {
    const level = item.risk_level || "";
    if (!["P1", "P2", "P3"].includes(level)) continue;
    const key = `${item.rule_id || item.title || ""}|${level}`;
    if (!grouped.has(key)) grouped.set(key, {level, title: item.title || item.rule_name || "未命名问题", items: []});
    grouped.get(key).items.push(item);
  }
  return [...grouped.values()].sort((a, b) => (severityOrder[a.level] || 99) - (severityOrder[b.level] || 99) || a.title.localeCompare(b.title, "zh-CN"));
}

function riskSummaryRows() {
  return [...riskGroups]
    .filter(item => ["P1", "P2", "P3"].includes(item.risk_level))
    .sort((a, b) => (severityOrder[a.risk_level] || 99) - (severityOrder[b.risk_level] || 99) || String(a.title).localeCompare(String(b.title), "zh-CN"))
    .map(item => `<tr><td class="risk-level-cell"><span class="risk-badge risk-badge-${esc(item.risk_level)}">${esc(item.risk_level)}</span></td><td>${esc(item.title)}</td><td>${esc(item.summary || "该风险需要结合技术证据进一步确认。")}</td><td>${esc(item.impact || "可能影响平台稳定性、可用性或后续运维效率。")}</td><td>${esc(item.remediation_mode || "需结合场景评估")}</td><td>${esc(item.remediation_effort || "中")}</td><td>${esc(item.remediation || "建议按风险详情完成配置核查，处理后重新巡检确认。")}</td></tr>`);
}

function detailText(value, fallback = "无") {
  return value && String(value).trim() ? value : fallback;
}

function affectedList(value) {
  const text = detailText(value, "无");
  if (text === "无") return "<li>无</li>";
  return text.split(/[、；;]/).map(item => item.trim()).filter(Boolean).map(item => `<li>${esc(item)}</li>`).join("") || "<li>无</li>";
}

function checkCategoryLabel(item) {
  return item.category_label || "环境核验结果";
}

function businessSourceLabel(item) {
  const provided = item.business_source_label || "";
  if (provided) return provided;
  const type = item.object_type_label || item.object_type || "";
  if (type.includes("数据存储") || type === "Datastore") return "数据存储运行状态";
  if (type.includes("ESXi") || type === "HostSystem") return "ESXi 主机运行状态";
  if (type.includes("虚拟机") || type === "VirtualMachine") return "虚拟机运行状态";
  if (type.includes("集群") || type === "ClusterComputeResource") return "集群配置状态";
  if (type.includes("vCenter")) return "vCenter 管理平台";
  return "环境采集数据";
}

function certificateLicenseEvidenceRows() {
  return certificateLicenseEvidence.map(item => `<tr>
    <td>${esc(checkCategoryLabel(item))}</td>
    <td>${esc(item.object_type_label || "")}</td>
    <td>${esc(item.object_name || "")}</td>
    <td>${esc(item.result_status_label || item.result_status || "未知")}</td>
    <td>${esc(detailText(item.current_value_zh, "未记录"))}</td>
    <td>${esc(detailText(item.expected_value_zh, "按巡检基线执行"))}</td>
    <td>${esc(businessSourceLabel(item))}</td>
    <td>${esc(detailText(item.collected_at, "未记录"))}</td>
  </tr>
  <tr class="evidence-detail-row"><td colspan="8">
    <div class="kv evidence-kv audit-kv">
      <div>说明</div><div>${esc(detailText(item.explanation_zh || item.evidence_summary_zh, "已根据采集到的环境状态完成核验。"))}</div>
    </div>
  </td></tr>`);
}

function riskDetails() {
  const groups = groupedRisks();
  if (!groups.length) return `<div class="empty-note">本次未发现明确风险项。</div>`;
  return groups.map(group => {
    const rows = group.items || [];
     const details = table(["受影响组件", "当前状态", "证据摘要", "建议动作"], rows.map(item => `<tr><td>${esc(item.object_name || "未采集")}</td><td>${esc(detailText(item.observed_detail_zh, "未采集"))}</td><td>${esc(detailText(item.evidence_summary_zh, "已根据采集数据完成判断。"))}</td><td>${esc(detailText(item.recommended_action_zh || item.remediation, "按整改建议处理后复跑巡检。"))}</td></tr>`));
     return `<section class="risk-group"><details><summary><span class="risk-badge risk-badge-${esc(group.level)}">${esc(group.level)}</span>${esc(group.title)}　<span class="subtle">影响对象：${rows.length}</span></summary><div class="body"><h4>受影响对象与技术证据</h4>${details}<div class="subtle evidence-label">参考说明 · 故障详情 / 告警详情 / 异常详情</div></div></details></section>`;
  }).join("");
}

function renderRiskIssues() {
  document.getElementById("findings").innerHTML = `
     <h2>问题与整改</h2>
    <div class="note">本节汇总本次巡检发现的风险项，建议按风险等级和影响范围安排整改。</div>
    <h3>风险项汇总</h3>
     ${table(["等级", "风险标题", "问题说明", "可能影响", "整改方式", "整改复杂度", "整改建议"], riskSummaryRows(), "risk-summary-table")}
    <h3>风险详情</h3>
    ${findings.length ? riskDetails() : `<div class="empty-note">本次未发现明确风险项。</div>`}`;
}

function deltaText(delta, mode = "count") {
  if (!delta || delta.delta === null || delta.delta === undefined || delta.delta === "") return "无对比";
  const value = Number(delta.delta);
  if (Number.isNaN(value) || value === 0) return "无变化";
  const abs = Math.abs(value);
  if (mode === "score") return value > 0 ? `提升 ${abs}` : `下降 ${abs}`;
  return value > 0 ? `增加 ${abs}` : `减少 ${abs}`;
}

function deltaMetric(label, delta, mode = "count") {
  const base = delta || {};
  const from = base.baseline === null || base.baseline === undefined ? "--" : base.baseline;
  const to = base.comparison === null || base.comparison === undefined ? "--" : base.comparison;
  return `<div class="card compact"><div class="label">${esc(label)}</div><div class="value">${esc(from)} → ${esc(to)}</div><div class="subtle">${esc(deltaText(base, mode))}</div></div>`;
}

function historyRiskRows(items, emptyText) {
  if (!items || !items.length) return `<div class="empty-note">${esc(emptyText)}</div>`;
  return table(["等级", "风险名称", "影响对象", "变化", "当前状态与建议"], items.map(item => `<tr>
    <td class="risk-${esc(item.risk_level)}">${esc(item.risk_level)}</td>
    <td>${esc(item.title)}</td>
    <td>${esc(item.object_type_label || "")} · ${esc(item.object_name || "")}</td>
    <td>${esc(item.change_status_label || "")}</td>
    <td>当前状态：${esc(detailText(item.current_observed, "未记录"))}<br>建议：${esc(item.title === "虚拟机存在快照" || /快照/.test(item.title || "") ? "核对快照用途、创建时间和占用空间；仍需保留则登记保留期限并定期复核；无业务需求时在合适窗口删除或合并。" : detailText(item.expected_state, "按健康基线执行"))}</td>
  </tr>`));
}

function historyAssetRows(items, emptyText) {
  if (!items || !items.length) return `<div class="empty-note">${esc(emptyText)}</div>`;
  return table(["资产类型", "资产名称", "位置", "变化"], items.map(item => `<tr>
    <td>${esc(item.object_type_label || "")}</td>
    <td>${esc(item.object_name || "")}</td>
    <td>${esc(detailText(item.location, "未记录"))}</td>
    <td>${esc(item.change_status_label || "")}</td>
  </tr>`));
}

function renderHistoryComparison() {
  const state = historyComparison.state || "empty";
  if (state === "empty") {
    document.getElementById("history").innerHTML = `
      <h2>历史对比摘要</h2>
      <div class="empty-note">暂无评估数据，完成首次评估后可查看历史趋势。</div>`;
    return;
  }
  if (state === "single_run") {
    document.getElementById("history").innerHTML = `
      <h2>历史对比摘要</h2>
      <div class="empty-note">当前只有 1 次评估，完成第二次评估后可生成历史对比。</div>`;
    return;
  }
  if (state !== "ready") {
    // environment_mismatch / run_unavailable 等不可比状态：只显示明确提示，不显示任何差异数据。
    document.getElementById("history").innerHTML = `
      <h2>历史对比摘要</h2>
      <div class="empty-note">${esc(historyComparison.summary_text || "暂无可比的历史巡检记录。")}</div>`;
    return;
  }
  const risk = historyComparison.risk_counts || {};
  const asset = historyComparison.asset_counts || {};
  const risks = historyComparison.risk_changes || {};
  const assetChanges = historyComparison.asset_changes || {};
  document.getElementById("history").innerHTML = `
    <h2>历史对比摘要</h2>
    <div class="note">${esc(historyComparison.summary_text || "已完成两次评估对比。")}</div>
    <div class="kv compact-kv">
      <div>基准评估</div><div>${esc(historyComparison.baseline_label || "未记录")}</div>
      <div>对比评估</div><div>${esc(historyComparison.comparison_label || "未记录")}</div>
    </div>
    <h3>变化概览</h3>
    <div class="grid overview-grid">

      ${deltaMetric("P1 风险", risk.P1)}
      ${deltaMetric("P2 风险", risk.P2)}
      ${deltaMetric("P3 风险", risk.P3)}
      ${deltaMetric("Host", asset.host)}
      ${deltaMetric("VM", asset.vm)}
      ${deltaMetric("Datastore", asset.datastore)}
    </div>
    <div class="tracking-columns">
      <section><h3>新增风险</h3>${historyRiskRows(risks.new || [], "本次未发现新增风险。")}</section>
      <section><h3>本次未再检出</h3>${historyRiskRows(risks.closed || [], "本次未发现未再检出风险。")}</section>
    </div>
    <section class="risk-group"><h3>持续风险</h3>${historyRiskRows(risks.persistent || [], "本次未发现持续风险。")}</section>
    <div class="tracking-columns">
      <section><h3>新增资产</h3>${historyAssetRows(assetChanges.new || [], "本次未发现新增资产。")}</section>
      <section><h3>删除资产</h3>${historyAssetRows(assetChanges.removed || [], "本次未发现删除资产。")}</section>
    </div>`;
}

function renderAppendix() {
  document.getElementById("appendix").innerHTML = `
    <h2>附录</h2>
    <h3>证书与授权核验结果</h3>
    <div class="note">本节展示 vCenter / ESXi 证书与 VMware License 状态，用于确认环境关键状态已被核对。</div>
    ${table(["核验类别", "对象类型", "对象名称", "状态", "当前状态", "建议状态", "数据来源", "采集时间"], certificateLicenseEvidenceRows(), "check-evidence-table")}
    `;
}

function renderVcenter() {
  const env = ctx.environment_info || {};
  document.getElementById("vcenter").innerHTML = `
    <h2>vCenter</h2>
    <div class="kv compact-kv">
      <div>vCenter</div><div>${esc(env.vcenter || "未采集")}</div>
      <div>版本</div><div>${esc(env.vcenter_version || "未采集")}</div>
      <div>采集方式</div><div>${esc(env.collection_mode_label || "未采集")}</div>
      <div>证书与 License</div><div>详见附录核验结果</div>
    </div>
    <h3>资产清单</h3>
    ${table(["对象类型", "对象名称", "位置"], assetInventoryRows().map(item => `<tr><td>${esc(objectTypeLabels[item.type] || item.type)}</td><td>${esc(item.object_name)}</td><td>${esc(item.asset_location || item.object_path)}</td></tr>`))}`;
}

function renderVsan() {
  const node = document.getElementById("vsan");
  if (!node || !vsanSummary || vsanSummary.status === "not_applicable") {
    return;
  }
  const capacity = vsanSummary.capacity || {};
  const network = vsanSummary.network || {};
  const collectionLabel = {collected: "已采集", unavailable: "部分采集", partial: "部分采集", unknown: "未确认"}[vsanSummary.collection_status || vsanSummary.status] || "未确认";
  const categories = vsanSummary.report_categories || [];
  const categoryMap = Object.fromEntries(categories.map(item => [item.category_id, item]));
  const category = id => categoryMap[id] || {risk_level: "未确认", status: "未确认", conclusion: "数据未确认"};
  const localizeLabel = value => String(value || "")
    .replace(/\bStorage Policy\b/gi, "存储策略")
    .replace(/\bObject\b/gi, "对象")
    .replace(/\bHealth\b/gi, "健康")
    .replace(/\bCapacity\b/gi, "容量")
    .replace(/\bNetwork\b/gi, "网络")
    .replace(/\bResync\b/gi, "重同步");
  const capLabel = {normal: "正常", attention: "建议关注", high: "高容量水位，重点关注", unknown: "未确认"}[capacity.status] || "未确认";
  const storagePolicy = vsanSummary.storage_policy_summary || {};
  const policyAvailable = Object.keys(storagePolicy).length > 0 && (storagePolicy.policy_categories || []).length > 0;
  const policyRows = (storagePolicy.policy_categories || []).map(item => `<tr><td>${esc(item.policy_name || "未命名策略")}</td><td>${esc(item.policy_uuid || "未记录")}</td><td>${esc(item.checked_count == null ? "未确认" : item.checked_count)}</td><td>${esc(item.compliant_count == null ? "未确认" : item.compliant_count)}</td><td>${esc(item.noncompliant_count == null ? "未确认" : item.noncompliant_count)}</td><td>${esc(item.unknown_count == null ? "未确认" : item.unknown_count)}</td></tr>`).join("");
  const cards = [
    ["采集状态", collectionLabel], ["总体健康", category("VSAN-CLUSTER-HEALTH").status],
    ["磁盘组 / 缓存盘 / 容量盘", `${vsanSummary.disk_group_count == null ? "未确认" : vsanSummary.disk_group_count} / ${vsanSummary.cache_disk_count == null ? "未确认" : vsanSummary.cache_disk_count} / ${vsanSummary.capacity_disk_count == null ? "未确认" : vsanSummary.capacity_disk_count}`],
    ["对象 / VMDK", `${vsanSummary.object_count == null ? "未确认" : vsanSummary.object_count} / ${vsanSummary.vmdk_count == null ? "未确认" : vsanSummary.vmdk_count}`],
    ["重同步对象数", vsanSummary.resync_object_count == null ? "未确认" : vsanSummary.resync_object_count],
    ["容量使用率", capacity.used_percent == null ? "未确认" : `${capacity.used_percent}%`],
  ];
  const issueRows = [...(vsanSummary.health_issues || []), ...(vsanSummary.disk_issues || []), ...(vsanSummary.object_issues || [])].map(item => `<tr><td>${esc(item.component || item.host || item.disk || "vSAN")}</td><td>${esc(item.status || "未确认")}</td><td>${esc(item.summary || "")}</td></tr>`);
  const categoryRows = categories.map(item => `<tr><td>${esc(localizeLabel(item.title))}</td><td>${esc(item.risk_level)}</td><td>${esc(item.status)}</td><td>${esc(localizeLabel(item.conclusion))}</td></tr>`);
  const diskRows = (vsanSummary.disk_details || []).map(item => `<tr><td>${esc(item.host)}</td><td>${esc(item.disk_group)}</td><td>${esc(item.role)}</td><td>${esc(item.device)}</td><td>${esc(item.health)}</td></tr>`);
  const vmkRows = (network.vmkernels || []).map(item => `<tr><td>${esc(item.host_name || item.host || "未记录")}</td><td>${esc(item.device || "未记录")}</td><td>${esc(item.ip_address || "未记录")}</td><td>${esc(item.subnet_mask || "未记录")}</td><td>${esc(item.network_label || item.portgroup || "未记录")}</td><td>${esc(item.mtu == null ? "未记录" : item.mtu)}</td></tr>`);
  const diskIssueStates = new Set(["异常", "故障", "需关注", "red", "yellow", "error", "failed", "unhealthy", "offline", "degraded"]);
  const diskHasIssue = (vsanSummary.disk_details || []).some(item => diskIssueStates.has(String(item.health || "").trim().toLowerCase())) || (vsanSummary.disk_issues || []).length > 0;
  const capacityConclusion = capacity.used_percent == null ? "容量使用率未采集，当前不能判断容量水位。" : capLabel === "正常" ? `当前容量使用率为 ${capacity.used_percent}%，低于 75% 关注阈值，整体容量水位正常。` : `当前容量使用率为 ${capacity.used_percent}%，当前容量水位为${capLabel}。`;
  node.innerHTML = `
    <h2>vSAN</h2>
    <div class="note">判定说明：正常表示本次采集未发现该项异常；需关注表示发现异常或达到阈值；未确认表示数据不足，不能按正常处理。</div>
    <div class="grid vsan-summary-grid">${cards.map(item => metric(item[0], item[1])).join("")}</div>
    <h3>检查项结论</h3>
    <div class="vsan-table-scroll">${table(["检查项", "等级", "本次结论", "说明"], categoryRows, "vsan-checks-table")}</div>
    <h3>磁盘与磁盘组明细</h3>
    <details ${diskHasIssue ? "open" : ""}><summary>查看磁盘明细（${diskRows.length}）</summary><div class="vsan-table-scroll">${table(["主机", "磁盘组", "磁盘角色", "设备名称", "健康状态"], diskRows, "vsan-disk-table")}</div></details>
    <h3>vSAN VMkernel 网络明细</h3>
    <details><summary>查看 VMkernel 明细（${vmkRows.length}）</summary><div class="vsan-table-scroll">${table(["主机", "设备", "IP", "子网", "网络标签", "MTU"], vmkRows, "vsan-vmk-table")}</div></details>
    <h3>容量结论</h3>
    <div class="note">${esc(capacityConclusion)} 阈值为 &lt;75% 正常、75%~&lt;80% 建议关注、≥80% 高容量水位。</div>
    ${policyAvailable ? `<h3>存储策略分类</h3>${table(["策略名称", "策略 UUID", "已检查", "合规", "不合规", "未确认"], policyRows)}` : ""}
    <details ${issueRows.length ? "open" : ""}><summary>查看 vSAN 异常明细（${issueRows.length}）</summary>${table(["组件", "状态", "说明"], issueRows)}</details>
    <details><summary>查看采集说明</summary><div class="note">重同步对象数大于 0 不会单独产生严重风险；容量阈值为 &lt;75% 正常、75%~&lt;80% 建议关注、≥80% 高容量水位。API 不可用时显示未确认。</div></details>`;
}

function activateModule() {
  const requested = (window.location.hash || "#overview").slice(1);
  const allowed = ["overview", "vcenter", "vsan", "findings", "history", "appendix"];
  const active = allowed.includes(requested) && document.getElementById(requested) ? requested : "overview";
  document.querySelectorAll(".report-module").forEach(item => item.classList.toggle("active", item.id === active));
  document.querySelectorAll(".nav a").forEach(item => item.classList.toggle("active", item.getAttribute("href") === `#${active}`));
}

renderOverview();
renderVcenter();
renderVsan();
renderRemediationTracking();
renderHistoryComparison();
renderRiskIssues();
renderAppendix();
window.addEventListener("hashchange", activateModule);
activateModule();"""

SINGLE_PAGE_REPORT_JS = r"""
const DATA = JSON.parse(document.getElementById("report-data").textContent);

function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function num(value) {
  if (value === null || value === undefined || value === "") return "";
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString("zh-CN", {maximumFractionDigits: 1}) : "";
}

function gb(value) {
  return value === null || value === undefined ? "" : `${num(value)} GB`;
}

function pct(value) {
  if (value === null || value === undefined || value === "") return "";
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(1)}%` : "";
}

function localTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "";
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hour12: false,
  }).format(date);
}

function summarySentence(value) {
  const text = String(value || "").trim().split(/[。！？]/, 1)[0].trim().replace(/[。！？]+$/, "");
  return text ? `${text}。` : "";
}

function summaryIssueText(item) {
  let current = String(item.current || "").trim();
  const clusterNames = (item.objects || []).map(object => object.name).filter(Boolean);
  if (item.title === "集群 HA 未启用") {
    current = `${num(clusterNames.length)} 个集群${clusterNames.length ? `（${clusterNames.join("、")}）` : ""}未启用 HA。`;
  } else if (item.title === "集群 DRS 未启用") {
    current = `${num(clusterNames.length)} 个集群${clusterNames.length ? `（${clusterNames.join("、")}）` : ""}未启用 DRS。`;
  }
  const remediation = String(item.remediation || "").trim().replace(/^建议[：:，,\s]*/, "");
  return [
    summarySentence(current),
    summarySentence(item.impact),
    summarySentence(remediation ? `建议${remediation}` : "建议完成处理后复核对应状态"),
  ].filter(Boolean).join(" ");
}

function table(headers, rows, className = "") {
  if (!rows || !rows.length) return "";
  const cls = className ? ` class="${esc(className)}"` : "";
  return `<div class="table-scroll"><table${cls}><thead><tr>${headers.map(x => `<th>${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function usageBar(value, tone = "storage") {
  if (value === null || value === undefined || value === "") return "";
  const raw = Number(value);
  if (!Number.isFinite(raw)) return "";
  const n = Math.max(0, Math.min(100, raw));
  const level = raw < 75 ? "low" : raw < 80 ? "mid" : "high";
  return `<div class="usage-track ${esc(tone)} ${level}" role="img" aria-label="使用率 ${pct(raw)}"><span class="used" style="width:${n}%"></span><span class="free" style="width:${100 - n}%"></span></div>`;
}

function storageRows(items) {
  return items.map(item => {
    const used = item.usagePct === null || item.usagePct === undefined || item.usagePct === "" ? NaN : Number(item.usagePct);
    const split = Number.isFinite(used) ? `已用 ${pct(used)}；可用 ${pct(100 - used)}` : "";
    return `<tr><td>${esc(item.name)}</td><td>${esc(item.type)}</td><td>${esc(gb(item.totalGb))}</td><td>${esc(gb(item.usedGb))}</td><td><div class="usage-cell">${usageBar(item.usagePct)}<span>${esc(split)}</span></div></td></tr>`;
  });
}

function hostRows(items) {
  return items.map(item => {
    const cpu = Number(item.cpuPct), memory = Number(item.memoryPct);
    const health = Number.isFinite(cpu) && Number.isFinite(memory) && cpu < 80 && memory < 80 ? "正常" : "需关注";
    const state = String(item.connectionState || "").trim().toLowerCase();
    const maintenance = item.maintenanceMode === true || ["true", "1", "yes"].includes(String(item.maintenanceMode || "").toLowerCase());
    const connection = maintenance || ["maintenance", "maintenance_mode", "inmaintenance", "in_maintenance", "维护模式"].includes(state)
      ? "维护模式"
      : ["connected", "已连接"].includes(state)
        ? "已连接"
        : ["notresponding", "not_responding", "disconnected", "unresponsive", "未响应"].includes(state)
          ? "未响应"
          : "—";
    return `<tr><td>${esc(item.name)}</td><td>${health}</td><td>${connection}</td><td>${esc(pct(item.cpuPct))}</td><td>${esc(pct(item.memoryPct))}</td></tr>`;
  });
}

function vmRows(items) {
  return items.map(item => `<tr><td>${esc(item.name)}</td><td>${esc(item.hostName)}</td><td>${esc(item.powerState)}</td><td>${esc(gb(item.diskGb))}</td></tr>`);
}

function renderVsan(item) {
  const v = item.vsan;
  if (!v) return "";
  const validUsage = v.usagePct !== null && v.usagePct !== undefined && v.usagePct !== "" && Number.isFinite(Number(v.usagePct));
  const disks = (v.disks || []).map(d => `<tr><td>${esc(d.host)}</td><td>${esc(d.group)}</td><td>${esc(d.role)}</td><td>${esc(d.device)}</td><td>${esc(d.diskState)}</td></tr>`);
  const adapters = (v.adapters || []).map(a => `<tr><td>${esc(a.host)}</td><td>${esc(a.device)}</td><td>${esc(a.ip)}</td><td>${esc(a.subnet)}</td><td>${esc(a.label)}</td><td>${esc(a.mtu)}</td></tr>`);
  const capacity = validUsage ? `
    <div class="vsan-usage">${usageBar(v.usagePct, "vsan-usage-bar")}<div class="usage-values">总计 ${esc(gb(v.totalGb))}　已用 ${esc(gb(v.usedGb))}　可用 ${esc(gb(v.freeGb))}　使用率 ${esc(pct(v.usagePct))}</div></div>
    <p class="threshold-note">使用率低于 75% 为正常，75% 至低于 80% 为需关注，80% 及以上为高水位。</p>` : "";
  const capacityFold = capacity ? `<details class="vsan-fold"><summary>vSAN 容量</summary>${capacity}</details>` : "";
  const disksFold = disks.length
    ? `<details class="vsan-fold"><summary>vSAN 磁盘组（${disks.length}）</summary>${table(["主机", "磁盘组", "磁盘角色", "设备名称", "健康状态"], disks, "vsan-disk-table")}</details>`
    : "";
  const networkFold = adapters.length
    ? `<details class="vsan-fold"><summary>vSAN 网络（${adapters.length}）</summary>${table(["主机", "设备", "IP", "子网", "网络标签", "MTU"], adapters, "vsan-vmk-table")}</details>`
    : "";
  const syncing = v.syncObjects === null || v.syncObjects === undefined || v.syncObjects === "" ? NaN : Number(v.syncObjects);
  const hasSyncData = Number.isFinite(syncing) && (syncing === 0 || (syncing > 0 && v.syncGb !== null && v.syncGb !== undefined));
  const objectInfo = [];
  if (v.objects !== null && v.objects !== undefined) objectInfo.push(`vSAN 对象 ${esc(num(v.objects))}`);
  if (v.vmdks !== null && v.vmdks !== undefined) objectInfo.push(`VMDK ${esc(num(v.vmdks))}`);
  if (Number.isFinite(syncing) && syncing === 0) objectInfo.push("当前无重同步");
  const resyncDetails = Number.isFinite(syncing) && syncing > 0 && v.syncGb !== null && v.syncGb !== undefined
    ? `<p class="plain-line">当前有 ${esc(num(syncing))} 个对象正在重同步，待重同步数据 ${esc(gb(v.syncGb))}。</p>`
    : "";
  const objectsFold = objectInfo.length || hasSyncData
    ? `<details class="vsan-fold"><summary>vSAN 对象</summary>${objectInfo.length ? `<p class="plain-line">${objectInfo.join("；")}。</p>` : ""}${resyncDetails}</details>`
    : "";
  return `${capacityFold}${disksFold}${networkFold}${objectsFold}`;
}

function renderCluster(cluster) {
  const stores = cluster.stores || [];
  const storageDetails = stores.length
    ? `<details class="cluster-storage"><summary>${esc(cluster.name)} 数据存储（${num(stores.length)}）</summary>${table(["名称", "类型", "总容量", "已用容量", "使用率"], storageRows(stores))}</details>`
    : "";
  return `<article class="cluster-block"><h3>${esc(cluster.name)}</h3>
    ${cluster.hosts.length ? `<h4>主机</h4>${table(["主机名", "健康", "连接", "CPU 使用率", "内存使用率"], hostRows(cluster.hosts))}` : ""}
    ${cluster.vms.length ? `<details><summary>虚拟机（${cluster.vms.length}）</summary>${table(["虚拟机名称", "所在主机", "电源状态", "虚拟磁盘容量"], vmRows(cluster.vms))}</details>` : ""}
    ${storageDetails}${renderVsan(cluster)}</article>`;
}

function renderSummary() {
  const s = DATA.summary || {};
  const time = [localTime(s.startedAt), localTime(s.finishedAt)].filter(Boolean).join(" — ");
  const problems = (DATA.problems || []).filter(item => !/vsan/i.test(String(item.title || "")));
  const vcenterLead = problems.length
    ? "vCenter 环境目前运行正常，但存在以下情况需要处理："
    : "vCenter 环境目前运行正常，本次未发现需要处理的情况。";
  const lines = problems.map((item, i) => `<li><span>${i + 1}.</span><span>${esc(summaryIssueText(item))}</span></li>`).join("");
  const vcenterSummary = `<div class="summary-vcenter"><p class="judgement ${problems.length ? "attention" : "normal"}">${esc(vcenterLead)}</p>${lines ? `<ol class="summary-issues">${lines}</ol>` : ""}</div>`;
  const vsanCluster = (DATA.environment?.clusters || []).find(cluster => cluster.vsan);
  const vsanSummary = vsanCluster ? renderVsanSummary(vsanCluster) : "";
  document.getElementById("summary").innerHTML = `<h2>1. 总结</h2><div class="summary-panel"><p class="inspection-time">巡检时间：${esc(time)}</p>${vcenterSummary}${vsanSummary}</div>`;
}

function renderVsanSummary(cluster) {
  const vsan = cluster.vsan || {};
  const issues = vsan.issues || [];
  if (issues.length) {
    const rows = issues.map((item, index) => `<li><span>${index + 1}.</span><span>${esc(summaryIssueText(item))}</span></li>`).join("");
    return `<div class="summary-vsan"><p class="judgement attention">vSAN 集群目前运行正常，但存在以下情况需要处理：</p><ol class="summary-issues">${rows}</ol></div>`;
  }
  const disks = vsan.disks || [];
  const normalDisks = disks.filter(disk => String(disk.diskState || "").trim() === "正常").length;
  const diskStatus = disks.length && normalDisks === disks.length
    ? `${num(disks.length)} 块磁盘状态正常`
    : `${num(normalDisks)} / ${num(disks.length)} 块磁盘状态正常`;
  const hasSyncCount = vsan.syncObjects !== null && vsan.syncObjects !== undefined && vsan.syncObjects !== "";
  const syncCount = hasSyncCount ? Number(vsan.syncObjects) : NaN;
  const syncStatus = Number.isFinite(syncCount) && syncCount === 0
    ? "当前无重同步"
    : Number.isFinite(syncCount) && syncCount > 0
      ? `当前有 ${num(syncCount)} 个对象正在重同步`
      : "重同步状态暂无数据";
  return `<p class="summary-vsan">vSAN 集群的配置和当前运行状况正常。集群共 ${num(cluster.hosts?.length || 0)} 台主机，${diskStatus}，容量使用率 ${esc(pct(vsan.usagePct))}，${syncStatus}。</p>`;
}

function renderEnvironment() {
  const e = DATA.environment || {};
  const identity = (e.identity || []).map(x => {
    const value = x.label === "巡检时间" ? String(x.value || "").slice(0, 10) : x.value;
    return `<tr><th>${esc(x.label)}</th><td>${esc(value)}</td></tr>`;
  });
  const scaleItems = e.scale || [];
  const scale = scaleItems.length
    ? table(scaleItems.map(item => item.label), [`<tr>${scaleItems.map(item => `<td>${esc(num(item.count))}</td>`).join("")}</tr>`], "environment-scale")
    : "";
  const clusterList = e.clusters || [];
  const clusterRows = clusterList.map(cluster => `<tr><td>${esc(cluster.name)}</td><td>${esc(cluster.kind)}</td><td>${esc(num((cluster.hosts || []).length))}</td><td>${esc(cluster.ha || "—")}</td><td>${esc(cluster.drs || "—")}</td></tr>`);
  const clusterFacts = clusterRows.length ? `<h3>集群属性</h3>${table(["集群", "类型", "主机数", "HA", "DRS"], clusterRows, "cluster-facts")}` : "";
  const clusters = clusterList.map(renderCluster).join("");
  const certificates = renderCertificates(e.certificates);
  document.getElementById("environment").innerHTML = `<h2>2. 环境</h2>
    ${identity.length ? `<h3>巡检信息</h3>${table(["项目", "信息"], identity)}` : ""}
    ${certificates}
    ${scale ? `<h3>环境规模</h3>${scale}` : ""}
    ${clusterFacts}
    ${clusters || ""}`;
}

function renderCertificates(certificates) {
  if (!certificates) return "";
  const vcenters = certificates.vcenter || [];
  const clusters = certificates.clusters || [];
  const hosts = clusters.flatMap(cluster => cluster.hosts || []);
  const all = [...vcenters, ...hosts];
  if (!all.length) return "";
  const urgent = all.filter(item => item.expired || item.imminent);
  const countText = `本次检查 ${num(vcenters.length)} 个 vCenter 证书、${num(hosts.length)} 个 ESXi 主机证书`;
  let conclusion;
  if (urgent.length) {
    const named = urgent.map(item => `<span class="certificate-alert-text">${esc(item.name)} 的证书 ${esc(item.expiresOn)} 到期，${item.expired ? "已过期" : "即将过期"}。</span>`).join(" ");
    conclusion = `<p class="certificate-conclusion">${countText}；${named}</p>`;
  } else if (all.every(item => item.remainingDays >= 365)) {
    conclusion = `<p class="certificate-conclusion">${countText}，全部在 1 年以上到期，无即将过期或已过期证书。</p>`;
  } else {
    conclusion = `<p class="certificate-conclusion">${countText}，证书均未过期，无 3 个月内到期或已过期证书。</p>`;
  }
  const licenseLine = certificates.licenses?.length
    ? `<p class="certificate-license">授权类型：${esc(certificates.licenses.join("；"))}</p>`
    : "";
  const rows = items => items.map(item => {
    const rowClass = item.attention ? ` class="certificate-alert"` : "";
    const remaining = item.expired
      ? "已过期"
      : `${item.remainingLabel}${item.imminent ? "（即将过期）" : ""}`;
    return `<tr${rowClass}><td>${esc(item.name)}</td><td>${esc(item.expiresOn)}</td><td>${esc(remaining)}</td></tr>`;
  });
  const vcenterDetails = vcenters.length
    ? `<details class="certificate-details"><summary>vCenter 证书</summary>${table(["名称", "到期日", "剩余时间"], rows(vcenters), "certificate-table")}</details>`
    : "";
  const clusterDetails = clusters.filter(cluster => (cluster.hosts || []).length).map(cluster =>
    `<details class="certificate-details"><summary>${esc(cluster.name)}（${num(cluster.hosts.length)}）</summary>${table(["主机名", "到期日", "剩余时间"], rows(cluster.hosts), "certificate-table")}</details>`
  ).join("");
  return `<section class="certificate-block"><h3>证书</h3>${conclusion}${licenseLine}${vcenterDetails}${clusterDetails}</section>`;
}

function renderProblems() {
  const problems = DATA.problems || [];
  const summaryRows = problems.map(item => {
    const locations = new Set((DATA.environment?.clusters || []).map(cluster => cluster.name).filter(Boolean));
    const involved = new Set();
    for (const object of item.objects || []) {
      if (["集群 HA 未启用", "集群 DRS 未启用"].includes(item.title) && locations.has(String(object.name || ""))) {
        involved.add(String(object.name));
      }
      for (const segment of String(object.location || "").split(/[、/|,，]+/).map(value => value.trim())) {
        if (locations.has(segment)) involved.add(segment);
      }
    }
    const clusterText = involved.size ? [...involved].join("、") : (item.objects || []).some(object => /vCenter/i.test(object.location || "")) ? "vCenter" : "—";
    return `<tr><td class="problem-risk-${esc(item.level)}">${esc(item.level)}</td><td>${esc(item.title)}</td><td>${esc(num((item.objects || []).length))}</td><td>${esc(clusterText)}</td><td>${esc(summarySentence(item.current))}</td><td>${esc(summarySentence(item.remediation))}</td></tr>`;
  });
  const groups = ["P1", "P2", "P3"].map(level => {
    const rows = problems.filter(x => x.level === level);
    if (!rows.length) return "";
    return `<details class="problem-level problem-level-${level}"><summary>${level}（${rows.length}）</summary>${rows.map(x => {
      const objects = (x.objects || []).map(o => `<tr><td>${esc(o.name)}</td><td>${esc(o.location)}</td></tr>`);
      const objectTable = objects.length > 20
        ? `<details><summary>受影响对象（${objects.length}）</summary>${table(["名称", "所在主机或集群"], objects)}</details>`
        : table(["名称", "所在主机或集群"], objects);
      return `<details class="problem-item"><summary>${esc(x.title)}</summary><div class="problem-block problem-block-${level}"><p><strong>现状：</strong>${esc(x.current)}</p><p><strong>预期：</strong>${esc(x.expected)}</p><p><strong>影响：</strong>${esc(x.impact)}</p><div class="field-block"><strong>受影响对象：</strong>${objectTable}</div><p><strong>处理建议：</strong>${esc(x.remediation)}</p></div></details>`;
    }).join("")}</details>`;
  }).join("");
  document.getElementById("issues").innerHTML = `<h2>3. 问题</h2>${problems.length ? `${table(["等级", "问题", "数量", "涉及集群", "现状", "建议"], summaryRows, "problem-summary")}${groups}` : `<p class="plain-line">本次未发现需要整改的问题。</p>`}`;
}

function renderPassed() {
  const problemTitles = new Set((DATA.problems || []).map(item => String(item.title || "").trim().toLocaleLowerCase("zh-CN")));
  const labels = [...new Set(DATA.passedChecks || [])].filter(item => !problemTitles.has(String(item || "").trim().toLocaleLowerCase("zh-CN")));
  const rows = labels.map(x => `<tr><td>${esc(x)}</td><td>正常</td></tr>`);
  document.getElementById("passed").innerHTML = `<h2>4. 已通过的检查</h2>${rows.length ? table(["检查项", "结果"], rows) : ""}`;
}

function renderInventory() {
  const inventory = DATA.inventory || {};
  const hosts = inventory.hosts || [], vms = inventory.vms || [], stores = inventory.stores || [];
  const section = (label, list, headers, makeRows) => list.length ? `<details><summary>全部${label}（${list.length}）</summary>${table(headers, makeRows(list))}</details>` : "";
  document.getElementById("inventory").innerHTML = `<h2>5. 环境清单</h2>
    ${section("主机", hosts, ["主机名", "健康", "连接", "CPU 使用率", "内存使用率"], hostRows)}
    ${section("虚拟机", vms, ["虚拟机名称", "所在主机", "电源状态", "虚拟磁盘容量"], vmRows)}
    ${section("数据存储", stores, ["名称", "类型", "总容量", "已用容量", "使用率"], storageRows)}`;
}

renderSummary();
renderEnvironment();
renderProblems();
renderPassed();
renderInventory();
""";
