#let data = json("payload.json")
#let wording = data.wording

#let navy = rgb("#163B63")
#let blue = rgb("#2F72B7")
#let sky = rgb("#5C9BD1")
#let ink = rgb("#24364A")
#let muted = rgb("#607387")
#let border = rgb("#B9C8D6")
#let surface = rgb("#E9EEF3")
#let surface-2 = rgb("#F0F3F6")
#let pale-blue = rgb("#EDF3F8")
#let green = rgb("#398260")
#let pale-green = rgb("#E4F0E9")
#let amber = rgb("#B98220")
#let pale-amber = rgb("#F4EAD3")
#let red = rgb("#B84545")
#let pale-red = rgb("#F8EDED")
#let white = rgb("#FFFFFF")
#let field-text(value) = if type(value) == bool { repr(value) } else { str(value) }
#let field(label, value, suffix: "") = if value == none or field-text(value).trim() == "" { "" } else { label + field-text(value) + suffix }
#let join-fields(values) = values.filter(value => value != none and field-text(value).trim() != "").map(value => field-text(value)).join(" · ")

#set page(
  paper: "a4",
  flipped: true,
  margin: (left: 10mm, right: 10mm, top: 21mm, bottom: 16mm),
  fill: white,
  header: context [
    #grid(columns: (1fr, 1fr),
      text(size: 10pt, weight: "semibold", fill: navy)[#join-fields((data.customer_name, "虚拟化巡检报告"))],
      align(right)[#text(size: 10pt, fill: muted)[巡检日期：#data.report_date]],
    )
    #v(2pt)
    #line(length: 100%, stroke: 0.6pt + border)
  ],
  footer: context [
    #line(length: 100%, stroke: 0.5pt + border)
    #v(2pt)
    #grid(columns: (1fr, 1fr),
      text(size: 10pt, fill: muted)[采集日期：#data.capture_date],
      align(right)[#text(size: 10pt, fill: muted)[第 #counter(page).display("1 / 1", both: true) 页]],
    )
  ],
)
#set text(font: ("Microsoft YaHei", "SimSun"), size: 11pt, fill: ink)
#set par(leading: 0.65em, spacing: 4pt)
#show heading: set block(above: 5mm, below: 3mm)
#set table(inset: (x: 3pt, y: 2pt), stroke: (x: none, y: 0.45pt + border))

#let num(value) = if value == none { "" } else { str(value) }
#let known(value) = if value == none or value == "" { "" } else { value }
#let priority-color(level) = if level == "P1" { red } else if level == "P2" { amber } else { blue }
#let priority-fill(level) = if level == "P1" { pale-red } else if level == "P2" { pale-amber } else { pale-blue }
#let header-cell(value) = block(width: 100%, fill: navy, inset: (x: 4pt, y: 5pt), align(center)[#text(size: 10pt, weight: "bold", fill: white)[#value]])
#let body-cell(value) = block(width: 100%, fill: surface, inset: (x: 4pt, y: 10pt), text(size: 10pt, fill: ink)[#value])
#let compact-cell(value) = block(width: 100%, fill: surface, inset: (x: 3pt, y: 4pt), text(size: 10pt, fill: ink)[#value])
#let check-result-chip(value, level, positive) = {
  let fill-color = if positive { priority-fill(level) } else { pale-green }
  let text-color = if positive { priority-color(level) } else { green }
  block(width: 100%, fill: fill-color, inset: (x: 4pt, y: 4pt), radius: 2pt, align(center)[
    #text(size: 10pt, weight: "bold", fill: text-color)[#value]
  ])
}
#let appendix-cell(value) = block(width: 100%, fill: surface, inset: (x: 3pt, y: 2pt), text(size: 10pt, fill: ink)[#value])
#let story(value) = if value == none or value == "" { none } else { block(breakable: false, width: 100%, fill: rgb("#D5E3EF"), stroke: (left: 2pt + blue), inset: 7pt, radius: 3pt)[
  #block[#text(size: 11pt, weight: "semibold", fill: navy)[检查解读]]
  #v(2pt)
  #block[#text(size: 11pt, fill: ink)[#value]]
] }
#let page-title(number, title, subtitle: none) = {
  heading(level: 1, numbering: none, outlined: true, grid(columns: (12mm, 1fr), gutter: 2.5mm, align: (left, horizon),
    block(width: 10mm, fill: navy, inset: 4pt, radius: 2pt, align(center)[#text(size: 11pt, weight: "bold", fill: white)[#number]]),
    stack(dir: ttb, spacing: 5pt,
      block[#text(size: 15pt, weight: "bold", fill: navy)[#title]],
      if subtitle != none { block[#text(size: 10.5pt, weight: "regular", fill: muted)[#subtitle]] },
    ),
  ))
}
#let metric(label, value, detail: none, accent: blue) = if value == none or value == "" { none } else { block(width: 100%, fill: surface, stroke: 0.5pt + border, inset: 9pt, radius: 3pt)[
  #text(size: 10pt, fill: muted)[#label]
  #linebreak()
  #text(size: 17pt, weight: "bold", fill: accent)[#value]
  #if detail != none [#linebreak() #text(size: 10pt, fill: muted)[#detail]]
] }
#let bar(value, color: blue, height: 4mm, show-threshold: false) = {
  if value == none { none }
  else {
    let bounded = calc.min(calc.max(value, 0), 100)
    block(width: 100%, height: height, fill: surface-2, radius: 2pt)[
      #if bounded > 0 [#place(top + left, rect(width: bounded * 1%, height: height, fill: color, radius: 2pt))]
      #if show-threshold [#place(top + left, dx: 80%, rect(width: 1pt, height: height, fill: navy))]
    ]
  }
}
#let allocation-bar(value) = {
  if value == none { none }
  else {
    let bounded = calc.min(calc.max(value, 0), 125)
    let normal-width = calc.min(bounded, 100) / 125 * 100
    let overflow-width = calc.max(bounded - 100, 0) / 125 * 100
    block(width: 100%, height: 5mm, fill: surface-2, radius: 2pt)[
      #if normal-width > 0 [#place(top + left, rect(width: normal-width * 1%, height: 5mm, fill: blue, radius: 2pt))]
      #if overflow-width > 0 [#place(top + left, dx: normal-width * 1%, rect(width: overflow-width * 1%, height: 5mm, fill: amber, radius: 2pt))]
      #place(top + left, dx: 80%, rect(width: 1.2pt, height: 5mm, fill: navy))
    ]
  }
}
#let inspection-strip(scope) = {
  let total = calc.max(scope.total_checks, 1)
  grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
    metric(wording.check_total_label, str(scope.total_checks), accent: blue),
    metric("通过", str(scope.passed_checks), accent: green),
    metric("未通过", str(scope.problem_checks), accent: red),
  )
  v(2mm)
  block(width: 100%, height: 5mm, fill: surface-2, radius: 2pt)[
    #if scope.passed_checks > 0 [#place(top + left, rect(width: scope.passed_checks / total * 100%, height: 5mm, fill: green, radius: 2pt))]
    #if scope.problem_checks > 0 [#place(top + left, dx: scope.passed_checks / total * 100%, rect(width: scope.problem_checks / total * 100%, height: 5mm, fill: red, radius: 2pt))]
  ]
}
#let compact-row(left, right, color: blue) = block(width: 100%, fill: surface, inset: (x: 5pt, y: 3pt), radius: 2pt)[
  #grid(columns: (1fr, auto), gutter: 4mm,
    text(size: 10pt, fill: ink)[#left],
    text(size: 10pt, weight: "bold", fill: color)[#right],
  )
]
#let priority-bar(level, count, total) = block(breakable: false, fill: priority-fill(level), inset: 9pt, radius: 3pt)[
  #let share = count * 100 / calc.max(total, 1)
  #grid(columns: (auto, 1fr, auto), gutter: 2mm,
    text(size: 10pt, weight: "bold", fill: priority-color(level))[#level],
    block(width: 100%, height: 5mm, fill: white, radius: 2pt)[
      #if count > 0 [#rect(width: share * 1%, height: 5mm, fill: priority-color(level), radius: 2pt)]
    ],
    text(size: 10pt, weight: "bold")[#count 项],
  )
]
#let disk-group-card(group) = block(fill: surface, inset: 5pt, radius: 3pt)[
  #text(size: 10pt, weight: "bold", fill: navy)[#join-fields((group.host, group.name))]
  #v(1mm)
  #grid(columns: (1fr, 1fr), gutter: 1mm,
    body-cell("缓存盘 " + str(group.cache)), body-cell("容量盘 " + str(group.capacity)),
  )
  #if group.health_known [#text(size: 10pt, fill: muted)[健康状态正常 #group.healthy/#group.disks.len() 块]]
]
#let record-table(title, tag, columns, headers, rows, origin: none, namespace: "", split-cells: false) = {
  if rows.len() == 0 { return none }
  let visible = range(headers.len()).filter(i => rows.any(row => row.at(i) != none and row.at(i) != "" and row.at(i) != "未采集" and row.at(i) != "未记录"))
  if visible.len() == 0 { return none }
  let headers = visible.map(i => headers.at(i))
  let columns = visible.map(i => columns.at(i))
  let rows = rows.map(row => visible.map(i => row.at(i)))
  let marker = label(namespace + "evidence-" + tag)
  let start = if origin == none { marker } else { origin }
  [#table(columns: columns, inset: (x: 5pt, y: 5pt), stroke: 0.45pt + border, align: if split-cells { left + top } else { left + horizon },
    table.header(
      table.cell(colspan: headers.len(), fill: pale-blue)[#context {
        let continued = counter(page).get().first() > counter(page).at(start).first()
        text(size: 11pt, weight: "bold", fill: navy)[#title#if continued [（续页）] else if not title.ends-with("明细") [ 明细]]
      }],
      ..headers.map(name => table.cell(fill: navy, text(size: 10pt, weight: "bold", fill: white)[#name])),
    ),
    // Product rows are bounded, lossless fragments with repeated identity and
    // evidence cells. Keep each fragment together, not an unbounded raw row.
    ..rows.flatten().map(value => table.cell(breakable: false, text(size: 10.5pt)[#if value != "" and value != none and value != "未采集" and value != "未记录" [#value]])),
  )#marker]
}
#let action-card(item, namespace: "") = {
  let origin = label(namespace + "problem-" + item.rule_id)
  [#block(breakable: false, above: 5mm, below: 2mm)[
    #text(size: 13pt, weight: "bold", fill: priority-color(item.level))[#join-fields((item.level, item.title))]
    #v(2mm)
    #block[#text(size: 11pt)[影响对象：#item.count_label。]]
    #block[#text(size: 11pt)[#wording.current_label：#item.current]]
    #if item.expected != "" [#block[#text(size: 11pt)[#wording.expected_label：#item.expected]]]
    #if item.impact != "" [#block[#text(size: 11pt)[影响：#item.impact]]]
    #v(2mm)
    #block[#text(size: 11pt)[通用处理建议：#item.remediation]]
    #v(1mm)
    #if item.step_groups.len() > 0 {
      for group in item.step_groups {
        block(inset: (top: 2pt, bottom: 2pt))[#text(size: 11pt, weight: "semibold")[#group.title]]
        for (index, step) in group.steps.enumerate() {
          block(inset: (bottom: 2pt))[#text(size: 11pt)[#(str(index + 1) + ". " + step)]]
        }
      }
    } else {
      for step in item.steps_numbered { block(inset: (bottom: 2pt))[#text(size: 11pt)[#step]] }
    }
    #v(1mm)
    #block[#text(size: 10pt, fill: muted)[#join-fields((field("负责角色：", item.owner), field("工作量：", item.effort), field("复核方式：", item.verification)))]]
  ]#origin]
  record-table(item.title, item.rule_id, (1.6fr, 0.35fr, 0.85fr, 1.8fr), ("影响对象", wording.level_label, "所在范围", wording.basis_label), item.evidence_rows.map(row => (row.name, row.level, row.scope, row.basis)), origin: origin, namespace: namespace)
  v(3mm)
}
#let base-record-table = record-table
#let base-action-card = action-card
#let allocation-cell(value, display) = stack(dir: ttb, spacing: 0.5mm,
  text(size: 10pt, weight: "semibold")[#display],
  allocation-bar(value),
)
#let top5-row(item, value) = block(breakable: false, width: 100%, inset: (bottom: 8pt))[
  #stack(dir: ttb, spacing: 1.5mm,
    grid(columns: (auto, 1fr), gutter: 1.5mm, align: horizon,
      text(size: 10pt, weight: "bold", fill: blue)[#(str(item.rank) + ".")],
      text(size: 10pt, weight: "semibold")[#item.name],
    ),
    if item.host != none and item.host != "" and item.host != "未记录" {
      text(size: 10pt, fill: muted)[主机 #item.host]
    },
    if item.host_share_pct != none {
      text(size: 10pt, fill: muted)[#item.display_share_scope #item.host_share_text]
    },
    grid(columns: (1fr, auto), gutter: 2mm, align: horizon,
      bar(item.bar_pct, color: blue, height: 4mm),
      text(size: 10pt, weight: "bold")[#value],
    ),
  )
]
#let datastore-name(value) = block(inset: (bottom: 2pt), text(size: 10pt, weight: "semibold", font: ("Consolas", "Microsoft YaHei", "SimSun"))[#value])

#let integration-overview(report) = {
  page-title("01", report.title, subtitle: "本次选定产品与目标的只读检查")
  text(size: 11pt, weight: "bold")[#join-fields((report.customer, report.site))]
  par[#join-fields((field("范围：", report.scope), field("生成时间：", report.generated_at)))]
  story(report.summary)
  par[按产品展示状态、证据与限制，不计算跨产品健康分数。]
  record-table("本次选定目标与检查范围", "integration-targets", (1fr, 1fr, 2fr), ("产品与目标", "执行状态", "检查限制"),
    report.targets.map(target => (target.product_name + " " + target.name + "\n" + target.address,
      "采集：" + target.collection + "\n分析：" + target.analysis + "\n" + target.delivery, target.limits)))
  par[报告章节]
  for entry in report.navigation { par[ #entry ] }
  for limitation in report.limitations { par[ #limitation ] }
}

#if data.has_vcenter and data.product_report != none [
  #integration-overview(data.product_report)
]

#if data.has_vcenter [
#for data in if "legacy_reports" in data { data.legacy_reports } else { (data,) } [
#let namespace = if "vcenter_target_id" in data { data.vcenter_target_id + "-" } else { "" }
#let record-table(..args) = base-record-table(..args, namespace: namespace)
#let action-card(item) = base-action-card(item, namespace: namespace)
#if "vcenter_target_name" in data [
  #page-title("VC", "VC／vSAN 专项 " + data.vcenter_target_name, subtitle: "目标 ID：" + data.vcenter_target_id)
]
// 01 - Cover and decision summary
#grid(columns: (1.05fr, 0.95fr), gutter: 7mm, align: top,
  block(fill: navy, inset: 12mm, radius: 4pt)[
    #text(size: 11pt, weight: "semibold", fill: rgb("#BBD4E9"))[客户交付报告]
    #v(4mm)
    #text(size: 30pt, weight: "bold", fill: white)[虚拟化巡检报告]
    #v(3mm)
    #line(length: 100%, stroke: 1pt + rgb("#7096B9"))
    #v(5mm)
    #grid(columns: (25mm, 1fr), row-gutter: 3mm,
      text(fill: rgb("#BBD4E9"))[客户名称], text(weight: "semibold", fill: white)[#data.customer_name],
      text(fill: rgb("#BBD4E9"))[报告生成], text(weight: "semibold", fill: white)[#data.report_date],
      text(fill: rgb("#BBD4E9"))[平台版本], text(weight: "semibold", fill: white)[#join-fields((field("vCenter ", data.environment.vcenter_version), field("Build ", data.environment.vcenter_build)))],
    )
    #v(6mm)
    #block(breakable: false, fill: rgb("#234C72"), inset: 8pt, radius: 3pt)[
      #text(size: 10pt, weight: "bold", fill: white)[执行摘要]
      #v(2mm)
      #text(size: 10pt, fill: white)[#data.narratives.executive]
    ]
  ],
    stack(dir: ttb, spacing: 5mm,
    metric("集群", str(data.counts.clusters) + " 个", accent: blue),
    metric("主机", str(data.counts.hosts) + " 台", accent: blue),
    metric("虚拟机", str(data.counts.vms) + " 台", accent: blue),
    metric("存储", str(data.counts.datastores) + " 个", accent: blue),
  ),
)
#v(4mm)
#grid(columns: (1fr, 1fr), gutter: 3mm,
  metric(data.display_facts.counts.problem_label, str(data.problem_count), detail: join-fields((field("P1 ", data.risk_counts.P1), field("P2 ", data.risk_counts.P2), field("P3 ", data.risk_counts.P3))), accent: blue),
  metric(data.display_facts.counts.affected_label, str(data.issue_object_count), accent: blue),
)
#v(3mm)
#block(fill: pale-blue, inset: 7pt, radius: 3pt)[
  #block[#text(size: 10pt, weight: "bold", fill: navy)[总体结论：#data.delivery.conclusion]]
  #v(1mm)
  #block[#text(size: 10pt)[#data.delivery.explanation]]
  #v(1mm)
  #block[#text(size: 10pt, fill: muted)[#join-fields((data.delivery.environment, data.delivery.target, data.delivery.scope))]]
  #for item in data.delivery.priorities [#v(1mm) #block[#text(size: 10pt)[优先确认：#join-fields((item.level, item.title))（#item.objects 个对象）]]]
  #for limitation in data.delivery.limitations [#v(1mm) #block[#text(size: 10pt, fill: muted)[#limitation]]]
]
#v(3mm)
#if data.judgment_boundary != "" [
  #text(size: 10pt, fill: muted)[#data.judgment_boundary]
  #v(2mm)
]
#grid(columns: (1fr, 1fr, 1fr), gutter: 3mm,
  priority-bar("P1", data.risk_counts.P1, data.problem_count),
  priority-bar("P2", data.risk_counts.P2, data.problem_count),
  priority-bar("P3", data.risk_counts.P3, data.problem_count),
)
#v(2mm)
#if data.vsan.enabled or data.host_details.len() > 0 or data.datastores.len() > 0 [
  #text(size: 10pt, fill: muted)[#data.capacity_note]
  #v(1mm)
]
#if data.vsan.enabled [#grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
  if data.vsan.used_percent != none { metric("vSAN 容量使用", data.vsan.used_percent_text, detail: field("总量 ", data.vsan.total_display), accent: blue) },
  if data.vsan.healthy_disks != none and data.vsan.disk_count != none { metric("vSAN 物理盘", num(data.vsan.healthy_disks) + "/" + num(data.vsan.disk_count), detail: "正常 / 总数", accent: blue) },
  if data.vsan.resync_objects != none or data.vsan.resync_bytes != none {
    metric("vSAN 重同步", join-fields((if data.vsan.resync_objects != none { field("", data.vsan.resync_objects_text, suffix: " 对象") } else { "" },
      if data.vsan.resync_bytes != none { data.vsan.resync_bytes_text } else { "" })), accent: blue)
  },
)]

#v(6mm)

// 02 - Inspection scope results
#if data.scope.total_checks > 0 [
#page-title("02", "巡检范围结果", subtitle: wording.scope_subtitle)
#inspection-strip(data.scope)
#v(2mm)
#if data.recorded_results.available [#text(size: 11pt)[#data.display_facts.wording.failed_levels_text]]
#v(3mm)
#record-table("各检查范围结果", "scope-ranges", (0.9fr, 0.45fr, 0.4fr, 0.45fr, 1.7fr),
  ("检查范围", "结果条数", "通过", "未通过", "通过率"),
  data.scope.range_rows.map(item => (item.name, str(item.total), str(item.passed),
    check-result-chip(str(item.problems), item.highest_level, item.problems > 0),
    grid(columns: (1fr, auto), gutter: 2mm, align: horizon, bar(item.pass_rate, color: green, height: 4mm), text(size: 10pt)[#item.pass_rate_text]))))
#v(2mm)
#text(size: 10pt, weight: "semibold", fill: navy)[#data.scope.summary_text]
#v(3mm)
#if data.scope.problem_checks > 0 [
#grid(columns: (1fr, 1.08fr), gutter: 3mm, align: top,
  block(fill: surface, stroke: 0.5pt + border, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[未通过检查结果按等级分布]
    #v(2mm)
    #grid(columns: (44mm, 1fr), gutter: 2mm, align: center,
      block(width: 44mm, height: 44mm)[
        #image(if "scope_donut_file" in data { data.scope_donut_file } else { "scope_level_donut.svg" }, width: 44mm, height: 44mm)
      ],
      [
        #for item in data.scope.level_distribution {
          grid(columns: (8mm, 1fr), gutter: 1mm, align: horizon,
            text(size: 10pt, weight: "bold", fill: priority-color(item.level))[#item.level],
            text(size: 10pt)[#join-fields((field("", item.count, suffix: " 条"), if item.share_pct == none { "" } else { item.share_pct_text }))],
          )
          v(2mm)
        }
      ],
    )
  ],
  block(width: 100%, fill: surface, stroke: 0.5pt + border, inset: 7pt, radius: 3pt)[
    #[
      #text(size: 10pt, weight: "bold", fill: navy)[未通过最多的检查项]
      #v(2mm)
      #grid(columns: (1.7fr, 0.8fr, 0.55fr, 0.7fr), gutter: 0.7pt,
        header-cell("检查项"), header-cell("所属范围"), header-cell("等级"), header-cell("未通过条数"),
      )
      #for item in data.scope.top_failed_checks {
        grid(columns: (1.7fr, 0.8fr, 0.55fr, 0.7fr), gutter: 0.7pt, align: horizon,
          compact-cell(item.name), compact-cell(item.scope),
          check-result-chip(item.level, item.level, true), compact-cell(str(item.failed)),
        )
      }
    ]
  ],
)
]
]

#v(6mm)

// 03 - Overview and finding distribution
#page-title("03", "环境总览与问题分布", subtitle: "资产规模与需处理事项分布")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("集群", str(data.counts.clusters) + " 个"),
  metric("主机", str(data.counts.hosts) + " 台"),
  metric("虚拟机", str(data.counts.vms) + " 台"),
  metric("存储", str(data.counts.datastores) + " 个"),
)
#v(3mm)
#stack(dir: ttb, spacing: 4mm,
  stack(dir: ttb, spacing: 3mm,
  block(width: 100%, fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[需处理事项分布]
    #v(3mm)
    #for level in ("P1", "P2", "P3") {
      let value = data.risk_counts.at(level)
      let total = calc.max(data.problem_count, 1)
      grid(columns: (12mm, 1fr, 16mm), gutter: 2mm, align: horizon,
        text(weight: "bold", fill: priority-color(level))[#level],
        block(width: 100%, height: 7mm, fill: surface-2, radius: 2pt)[
          #if value > 0 [#place(top + left, rect(width: value / total * 100%, height: 7mm, fill: priority-color(level), radius: 2pt))]
        ],
        align(right)[#text(size: 10pt, weight: "bold")[#value 项]],
      )
      v(2mm)
    }
  ],
  block(breakable: false, width: 100%, fill: navy, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: white)[虚拟机运行状态]
    #v(1mm)
    #text(size: 13pt, weight: "bold", fill: white)[#join-fields((field("开机 ", data.counts.powered_on), field("关机 ", data.counts.powered_off), field("挂起 ", data.counts.suspended)))]
    #v(2mm)
    #bar(data.counts.powered_on * 100 / calc.max(data.counts.vms, 1), color: green, height: 5mm)
  ],
  block(width: 100%, fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[快照虚拟机]
    #v(1.5mm)
    #grid(columns: (1fr, auto), gutter: 2mm, align: horizon,
      text(size: 13pt, weight: "bold", fill: blue)[#data.display_facts.snapshots.overview_label],
      if data.counts.snapshot_max_age_days != none [#text(size: 10pt, fill: muted)[保留最久：#data.snapshot_max_age_text]],
    )
    #v(2mm)
    #text(size: 10pt)[#data.display_facts.snapshots.problem_label；#data.display_facts.snapshots.threshold_label。]
  ],
  ),
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[需处理类别 · 受影响对象数]
    #v(1.5mm)
    #v(1.5mm)
    #for item in data.category_rows {
      let width = item.objects * 100 / calc.max(data.max_issue_category_objects, 1)
      grid(columns: (1.1fr, 0.8fr, 14mm), gutter: 1mm, align: horizon,
        text(size: 10pt, fill: ink)[#item.title],
        block(width: 100%, height: 4.5mm, fill: white, radius: 1pt)[
          #if width > 0 [#rect(width: width * 1%, height: 4.5mm, fill: priority-color(item.level), radius: 1pt)]
        ],
        align(right)[#text(size: 10pt, weight: "bold")[#item.objects]],
      )
      v(1.3mm)
    }
    #if data.oldest_snapshots.len() > 0 [
      #block(breakable: false, above: 3mm)[
      #text(size: 10pt, weight: "bold", fill: navy)[保留最久的虚拟机]
      #v(1.5mm)
      #grid(columns: (1.5fr, 0.8fr, 0.7fr), gutter: 0.7pt,
        header-cell("虚拟机名称"), header-cell("所在集群"), header-cell("最长快照天数"),
      )
      #for item in data.oldest_snapshots {
        grid(columns: (1.5fr, 0.8fr, 0.7fr), gutter: 0.7pt,
          compact-cell(item.name), compact-cell(item.cluster), compact-cell(item.age_text),
        )
      }
      ]
    ]
  ],
)
#v(3mm)
#v(6mm)

// 04 - Cluster configuration
#page-title("04", "集群保护与配置", subtitle: "展示已确认的 HA、DRS、EVC 与 vMotion 状态")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("集群数", str(data.counts.clusters)),
  metric("HA 已启用", str(data.ha_chart.value) + "/" + str(data.ha_chart.total), accent: blue),
  metric("DRS 已启用", str(data.drs_chart.value) + "/" + str(data.drs_chart.total), accent: blue),
  metric("vMotion 主机", str(data.vmotion_host_total), accent: navy),
)
#v(5.5mm)
#for cluster in data.cluster_details {
  block(fill: surface, stroke: 0.5pt + border, inset: 10pt, radius: 3pt)[
    #grid(columns: (1.1fr, 0.8fr, 0.8fr, 0.8fr), gutter: 2mm,
      text(size: 10pt, weight: "bold", fill: navy)[#cluster.name],
      text(size: 10pt)[#join-fields((cluster.kind, field("", cluster.host_count, suffix: " 台主机"), field("", cluster.vm_count, suffix: " 台虚拟机")))],
      if cluster.ha_enabled != none [#text(size: 10pt)[HA #if cluster.ha_enabled [已启用] else [未启用]]],
      if cluster.drs_enabled != none [#text(size: 10pt)[DRS #if cluster.drs_enabled [已启用] else [未启用]]],
    )
    #v(2mm)
    #grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
      if cluster.admission_control != "" [#body-cell("HA 准入控制：" + cluster.admission_control)],
      if cluster.heartbeat_summary != "" [#body-cell("心跳数据存储：" + cluster.heartbeat_summary)],
      if cluster.isolation_response != "" [#body-cell("隔离响应：" + cluster.isolation_response)],
      if cluster.drs_behavior != "" [#body-cell("DRS 模式：" + cluster.drs_behavior)],
      if cluster.evc_enabled != "" [#body-cell("EVC：" + join-fields((cluster.evc_enabled, cluster.evc_mode)))],
      if cluster.vmotion_enabled_hosts != none [#body-cell("vMotion：" + num(cluster.vmotion_enabled_hosts) + "/" + str(cluster.host_count))],
      if cluster.cpu_model_count != none [#body-cell("CPU 型号数：" + num(cluster.cpu_model_count))],
      if cluster.memory_skew_pct != none [#body-cell("内存容量差异：" + cluster.memory_skew_text)],
    )
    #if cluster.cpu_usage_pct != none or cluster.memory_skew_pct != none [
      #v(2mm)
      #grid(columns: (1fr, 1fr), gutter: 2mm,
      if cluster.cpu_usage_pct != none [#block(fill: surface-2, inset: 4pt, radius: 2pt)[
        #text(size: 10pt, weight: "semibold")[#join-fields(("集群 CPU 使用率", cluster.cpu_usage_text))]
        #v(0.5mm)
        #bar(cluster.cpu_usage_pct, color: blue, height: 4mm)
      ]],
      if cluster.memory_skew_pct != none [#block(fill: surface-2, inset: 4pt, radius: 2pt)[
        #text(size: 10pt, weight: "semibold")[#join-fields(("主机内存容量差异", cluster.memory_skew_text))]
        #v(0.5mm)
        #bar(cluster.memory_skew_pct, color: blue, height: 4mm)
      ]],
      )
    ]
    #if cluster.host_names != "" [#text(size: 10pt, fill: muted)[主机：#cluster.host_names]]
    #if cluster.cpu_models != "" [#text(size: 10pt, fill: muted)[CPU 型号：#cluster.cpu_models]]
    #if cluster.drs_disabled_rules != "" [#v(1mm) #text(size: 10pt, fill: muted)[DRS 禁用规则：#cluster.drs_disabled_rules]]
    #if cluster.vmotion_missing_hosts != "" [#v(1mm) #text(size: 10pt, fill: amber)[未启用 vMotion 主机：#cluster.vmotion_missing_hosts]]
    #if cluster.maintenance_hosts != "" [#v(1mm) #text(size: 10pt, fill: muted)[维护模式主机：#cluster.maintenance_hosts]]
  ]
  v(3.5mm)
}
#grid(columns: (1fr, 1fr), gutter: 3mm,
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[HA 启用覆盖]
    #v(2mm)
    #bar(data.ha_chart.value * 100 / calc.max(data.ha_chart.total, 1), color: blue, height: 6mm)
    #text(size: 10pt, fill: muted)[#data.ha_chart.note]
  ],
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[DRS 启用覆盖]
    #v(2mm)
    #bar(data.drs_chart.value * 100 / calc.max(data.drs_chart.total, 1), color: blue, height: 6mm)
    #text(size: 10pt, fill: muted)[#data.drs_chart.note]
  ],
)
#v(3mm)
#story(data.narratives.clusters)

#v(6mm)

// 05 - Host status and current utilization
#page-title("05", "主机状态与资源使用", subtitle: "CPU/内存为采集时点值；" + wording.reference_80 + " 参考线用于定位，不代替持续性能分析")
#if data.hardware_issue_column [
  #grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
    metric("主机", str(data.counts.hosts), accent: blue),
    metric("已连接", str(data.connected_host_count) + "/" + str(data.counts.hosts), accent: green),
    metric("硬件异常", str(data.hardware_issue_total), accent: if data.hardware_issue_total > 0 { red } else { blue }),
    metric("最高主机内存使用率", data.highest_host_memory_text, detail: data.highest_host_memory_name, accent: blue),
  )
] else [
  #grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
    metric("主机", str(data.counts.hosts), accent: blue),
    metric("已连接", str(data.connected_host_count) + "/" + str(data.counts.hosts), accent: green),
    metric("最高主机内存使用率", data.highest_host_memory_text, detail: data.highest_host_memory_name, accent: blue),
  )
]
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[主机 CPU 使用率]
    #v(2mm)
    #for host in data.host_details {
      if host.cpu_pct != none {
        grid(columns: (0.55fr, 1fr, 12mm), gutter: 1mm, align: horizon,
          text(size: 10pt)[#host.name], bar(host.cpu_pct, color: blue, height: 7mm, show-threshold: true), align(right)[#host.cpu_pct_text],
        )
        v(2.5mm)
      }
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[主机内存使用率]
    #v(2mm)
    #for host in data.host_details {
      if host.memory_pct != none {
        grid(columns: (0.55fr, 1fr, 12mm), gutter: 1mm, align: horizon,
          text(size: 10pt)[#host.name], bar(host.memory_pct, color: blue, height: 7mm, show-threshold: true), align(right)[#host.memory_pct_text],
        )
        v(2.5mm)
      }
    }
  ],
)
#v(0.5mm)
#text(size: 10pt, fill: muted)[两图竖线均为 #(wording.reference_80) 参考线。]
#v(1.5mm)
#if data.hardware_issue_column and data.power_policy_column [
  #record-table("主机与硬件明细", "host-hardware", (1.1fr, 0.8fr, 0.7fr, 0.5fr, 0.6fr, 0.8fr, 0.7fr),
    ("ESXi 主机", "集群", "连接", "CPU 核心", "内存 " + data.host_memory_unit, "硬件异常", "电源策略"),
    data.host_details.map(host => (host.name, host.cluster, host.connection, num(host.cpu_cores), host.memory_capacity_text, str(host.hardware_issue_count) + " 项", host.power_policy)))
] else [
  #record-table("主机与硬件明细", "host-hardware", (1.2fr, 0.8fr, 0.7fr, 0.6fr, 0.8fr), ("ESXi 主机", "集群", "连接", "CPU 核心", "内存 " + data.host_memory_unit),
    data.host_details.map(host => (host.name, host.cluster, host.connection, num(host.cpu_cores), host.memory_capacity_text)))
]
#for host in data.host_details {
  if host.hardware_issue_summary != "" [#text(size: 10pt, fill: red)[#host.name：#host.hardware_issue_summary]]
}
#v(2mm)
#story(data.narratives.hosts)

#v(6mm)

// 06 - Resource allocation and Top 5
#page-title("06", "资源分配与 Top 5", subtitle: "资源分配使用主机配置容量；Top 5 展示 vCPU 数和同主机 VMDK 配置容量")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("物理 CPU 核心", num(data.counts.cpu_cores), accent: blue),
  metric("物理内存", data.counts.memory_total_text, accent: blue),
  metric("超配主机", data.overcommit_display, detail: "主机级资源分配标记", accent: if data.overcommit_host_count > 0 { amber } else { blue }),
  metric("Top 5 数据", str(data.top_vcpu.len() + data.top_capacity.len()) + " 项", accent: blue),
)
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[主机 vCPU:pCPU]
    #v(2mm)
    #for host in data.host_details {
      if host.vcpu_pcpu_ratio != none {
        grid(columns: (0.95fr, 1.05fr, 12mm), gutter: 1mm, align: horizon,
          text(size: 10pt)[#join-fields((host.name, if host.allocated_vcpu == none or host.cpu_cores == none { "" } else { num(host.allocated_vcpu) + "/" + num(host.cpu_cores) }))],
          bar(calc.min(host.vcpu_pcpu_ratio * 10, 100), color: if host.overcommit == true { amber } else { blue }, height: 5mm),
          align(right)[#num(host.vcpu_pcpu_ratio):1],
        )
        v(1.5mm)
      }
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[主机内存分配 · #(wording.reference_100) 容量线]
    #v(2mm)
    #for host in data.host_details {
      if host.memory_allocation_pct != none {
        grid(columns: (0.95fr, 1.05fr, 15mm), gutter: 1mm, align: horizon,
          text(size: 10pt)[#join-fields((host.name, if host.memory_allocated_gb == none or host.memory_capacity_gb == none { "" } else { host.memory_allocation_capacity_text }))],
          allocation-bar(host.memory_allocation_pct),
          align(right)[#host.memory_allocation_text],
        )
        v(1.5mm)
      }
    }
  ],
)
#v(0.5mm)
#text(size: 10pt, fill: muted)[橙色表示主机级资源超配或内存分配超过 #(wording.reference_100)；内存条按 #(wording.reference_0)-#(wording.reference_125) 缩放，竖线表示 #(wording.reference_100)。]
#v(1.5mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[vCPU 配置 Top 5 · 占同主机配置总量]
    #v(2mm)
    #for item in data.top_vcpu {
      top5-row(item, item.display)
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 10pt, weight: "bold", fill: navy)[VMDK 配置容量 Top 5]
    #v(2mm)
    #for item in data.top_capacity {
      top5-row(item, item.display)
    }
  ],
)
#v(1.5mm)
#text(size: 10pt, fill: muted)[#data.display_facts.top_labels.configuration_note]
#story(data.narratives.capacity)

#v(6mm)

// 07 - Datastore capacity and vSAN summary
#page-title("07", "数据存储容量与 vSAN 概况", subtitle: "按使用率排序展示数据存储；vSAN 正文给出容量、对象、磁盘组与重同步结论")
#if data.vsan.enabled and data.vsan.used_percent_text != "" and data.highest_datastore_usage != "" [
  #grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
    metric("数据存储", str(data.counts.datastores), accent: blue),
    metric("最高存储使用率", data.highest_datastore_usage, accent: if data.highest_datastore_pct >= 80 { red } else { blue }),
    metric("vSAN 容量使用率", data.vsan.used_percent_text, accent: blue),
  )
] else if data.vsan.enabled and data.vsan.used_percent_text != "" [
  #grid(columns: (1fr, 1fr), gutter: 2mm,
    metric("数据存储", str(data.counts.datastores), accent: blue),
    metric("vSAN 容量使用率", data.vsan.used_percent_text, accent: blue),
  )
] else if data.highest_datastore_usage != "" [
  #grid(columns: (1fr, 1fr), gutter: 2mm,
    metric("数据存储", str(data.counts.datastores), accent: blue),
    metric("最高存储使用率", data.highest_datastore_usage, accent: if data.highest_datastore_pct >= 80 { red } else { blue }),
  )
] else [
  #grid(columns: (1fr,), metric("数据存储", str(data.counts.datastores), accent: blue))
]
#v(1.5mm)
#text(size: 10pt, weight: "bold", fill: navy)[数据存储使用率 · #(wording.reference_75) 列示阈值 · #(wording.reference_80) 参考线]
#for store in data.datastores {
  grid(columns: (0.9fr, 1.8fr, 0.4fr, 0.55fr), gutter: 0.5pt, align: horizon,
    datastore-name(store.name),
    text(size: 10pt)[#join-fields((field("已用 ", store.used_text), field("可用 ", store.free_text), field("总量 ", store.total_text)))],
    align(right)[#text(size: 10pt, weight: "bold")[#store.usage_text]],
    text(size: 10pt, fill: muted)[#store.clusters.join("、")],
  )
  bar(store.usage, color: if store.usage != none and store.usage >= 80 { red } else if store.usage != none and store.usage >= 75 { amber } else { blue }, height: 3.5mm, show-threshold: true)
  v(1mm)
}
#if data.datastore_omitted_count > 0 [
  #text(size: 10pt, fill: muted)[其余 #data.datastore_omitted_count 个数据存储未在明细表展开。]
]
#v(1mm)
#if data.vsan.enabled [
  #if data.vsan.summary_metrics_available [
    #grid(columns: (1fr, 1fr, 1fr), gutter: 1.5mm,
      metric("vSAN 总容量", data.vsan.total_display, accent: blue),
      metric("vSAN 已用", join-fields((data.vsan.used_display, data.vsan.used_percent_text)), accent: blue),
      metric("对象 / VMDK", num(data.vsan.object_count) + " / " + num(data.vsan.vmdk_count), accent: blue),
    )
  ]
  #if data.vsan.disk_health_fully_known [
    #v(1mm)
    #metric("物理盘正常", num(data.vsan.healthy_disks) + "/" + num(data.vsan.disk_count), accent: if data.vsan.disk_count == data.vsan.healthy_disks { green } else { amber })
  ]
  #v(1mm)
  #if data.vsan.disk_group_count != none and data.vsan.cache_disk_count != none and data.vsan.capacity_disk_count != none [
    #compact-row("vSAN 磁盘组与盘型", join-fields((field("", data.vsan.disk_group_count, suffix: " 组"), field("缓存 ", data.vsan.cache_disk_count, suffix: " 块"), field("容量 ", data.vsan.capacity_disk_count, suffix: " 块"))), color: blue)
  ]
  #if data.vsan.resync_summary_text != "" [#compact-row("Resync 状态", data.vsan.resync_summary_text, color: if data.vsan.no_resync { green } else { amber })]
  #if data.vsan.vmkernel_interfaces.len() > 0 [
    #v(1mm)
    #text(size: 10pt)[vSAN 服务接口配置：#data.vsan.vmkernel_interfaces.join("；")。]
  ]
  #v(0.8mm)
  #grid(columns: (1fr, 1fr, 1fr), gutter: 1.5mm,
    ..data.disk_groups.map(group => disk-group-card(group)),
  )
]
#v(1mm)
#story(data.narratives.storage_vsan)

#v(6mm)

// 08 - VMkernel and physical network
#page-title("08", "VMkernel 网络与物理链路", subtitle: "网卡异常只列出被活动端口组使用且断链或速率异常的接口")
#grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
  metric("VMkernel 网络", data.network.vmkernel_display, accent: blue),
  metric("在用物理链路异常", data.network.pnic_anomaly_display, accent: if data.network.pnic_anomaly_count != none and data.network.pnic_anomaly_count > 0 { red } else { blue }),
  metric("已连接主机", str(data.connected_host_count) + "/" + str(data.counts.hosts), accent: blue),
)
#v(1.5mm)
#story(data.narratives.network)
#v(2mm)
#if data.network.vmkernels.len() > 0 [
#record-table("VMkernel 网络明细", "vmkernel", (0.9fr, 0.4fr, 0.8fr, 1.2fr, 0.9fr, 0.4fr), ("主机", "设备", "IP", "网络标签", "交换机", "MTU"), data.network.vmkernels.map(vmk => (vmk.host, vmk.device, vmk.ip, vmk.label, vmk.switch, vmk.mtu)))
]
#if data.network.pnic_anomalies.len() > 0 [
  #v(2mm)
  #record-table("物理网卡异常明细", "pnic", (0.9fr, 0.5fr, 1.8fr, 0.8fr), ("主机", "网卡", "使用端口组与角色", "当前状态"), data.network.pnic_anomalies.map(nic => (nic.host, nic.device, nic.portgroups, nic.state)))
]

#v(6mm)

// 09 - Host security and certificates
#page-title("09", "主机安全基线与证书", subtitle: "列出本次已确认的主机安全配置与证书信息")
#story(data.narratives.security)
#if data.host_security_present [
  #v(2mm)
  #record-table("主机安全基线", "host-security", (1fr, 3fr), ("主机", "已确认的配置状态"), data.host_details.filter(host => host.security_summary != "").map(host => (host.name, host.security_summary)))
]
#if data.certificates.vcenter.expiry != "" or data.certificates.vcenter.remaining_days != none or data.certificates.hosts.len() > 0 [
  #v(2mm)
  #let cert-rows = if data.certificates.vcenter.expiry != "" or data.certificates.vcenter.remaining_days != none { (("vCenter", data.certificates.vcenter.expiry, num(data.certificates.vcenter.remaining_days), data.certificates.vcenter.status, data.certificates.vcenter.date_source),) } else { () }
  #record-table("证书到期信息", "certificates", (1fr, 1fr, 0.6fr, 0.8fr, 1.5fr), ("对象", "到期日", "剩余天数", "保存的状态", "日期来源"), cert-rows + data.certificates.hosts.map(cert => (cert.host, cert.expiry, num(cert.remaining_days), cert.status, cert.date_source)))
  #for note in data.delivery.limitations.filter(note => note.starts-with("原始证书数据不一致")) [#v(2mm) #block[#text(size: 11pt, fill: amber)[#note]]]
  #if data.certificates.summary != "" [#v(1mm) #text(size: 10pt, fill: muted)[#data.certificates.summary]]
]
#if data.certificates.licenses.len() > 0 [#v(1mm) #text(size: 10pt, fill: muted)[授权：#data.certificates.licenses.join("；")]]

#v(6mm)

// 10 - Actionable findings
#if data.problems.len() == 0 [
  #block(breakable: false)[
    #page-title("10", "需处理事项与建议", subtitle: "未覆盖或证据不足的检查不能视为通过")
    #story(data.narratives.remediation)
  ]
] else [
#page-title("10", "需处理事项与建议", subtitle: "按处置优先级列出全部 P1-P3 问题、影响、处理步骤和复核方式")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("需处理类别", str(data.problem_count)),
  metric("P1", str(data.risk_counts.P1), accent: blue),
  metric("P2", str(data.risk_counts.P2), accent: blue),
  metric("P3", str(data.risk_counts.P3), accent: blue),
)
#v(2mm)
#story(data.narratives.remediation)
#v(2mm)
#for item in data.problems {
  action-card(item)
  v(0.8mm)
}
]

// Original alarm evidence is separate from the generic risk conclusion.
#if data.alarm_evidence.render_rows.len() > 0 [
  #v(5mm)
  #heading(level: 2, numbering: none)[vCenter 活动告警证据]
  #par[#wording.alarm_evidence_intro]
  #if data.alarm_evidence.render_rows.len() > 0 [
    #record-table("vCenter 活动告警", "vcenter-alarms", (1.8fr, 1.3fr, 0.6fr, 0.8fr, 1.2fr),
      ("告警名称", "告警对象", "原始状态", "确认状态", "源告警时间"), data.alarm_evidence.render_rows)
  ]
]

// 11 - Actual VM usage and appendices
#if data.top_cpu.len() > 0 or data.top_memory.len() > 0 [
#v(6mm)
#page-title("11", "虚拟机实际资源用量 Top 5", subtitle: "为巡检时刻的实际用量，与“资源分配与 Top 5”的配置量不同")
#text(size: 10pt, fill: muted)[#data.display_facts.top_labels.actual_note]
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 3mm, align: top,
  block(fill: surface, stroke: 0.5pt + border, inset: 7pt, radius: 3pt)[
    #block(breakable: false)[
      #text(size: 10pt, weight: "bold", fill: navy)[CPU 实际用量 · GHz]
      #v(2mm)
      #if data.top_cpu.len() > 0 { top5-row(data.top_cpu.first(), data.top_cpu.first().display) }
    ]
    #for item in data.top_cpu.slice(calc.min(1, data.top_cpu.len())) {
      top5-row(item, item.display)
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 7pt, radius: 3pt)[
    #block(breakable: false)[
      #text(size: 10pt, weight: "bold", fill: navy)[内存实际用量]
      #v(2mm)
      #if data.top_memory.len() > 0 { top5-row(data.top_memory.first(), data.top_memory.first().display) }
    ]
    #for item in data.top_memory.slice(calc.min(1, data.top_memory.len())) {
      top5-row(item, item.display)
    }
  ],
)
]

#if data.vsan.enabled and data.vsan.disk_details.len() > 0 [
  #v(5mm)
  #record-table("vSAN 物理盘明细", "vsan-disks", (1fr, 0.8fr, 0.8fr, 1.8fr, 0.6fr),
    ("主机", "磁盘组", "角色 / 数量", "设备标识 NAA", "状态"),
    data.vsan.disk_details.map(disk => (disk.host, disk.group, disk.role, disk.device, disk.health)))
]
#if data.appendix.iso_vms.len() > 0 [
  #v(5mm)
  #page-title("B", "附录 B · 虚拟机挂载 ISO 镜像")
  #record-table("虚拟机挂载 ISO 镜像", "iso", (1.7fr, 0.8fr, 1.7fr), ("虚拟机名称", "所在主机", "ISO 路径"),
    data.appendix.iso_vms.map(item => (item.name, item.host, item.iso_paths)))
]
#if data.appendix.powered_off_vms.len() > 0 [
  #v(5mm)
  #page-title("C", "附录 C · 存在关机的虚拟机")
  #record-table("关机虚拟机明细", "powered-off", (1.7fr, 0.8fr, 1.3fr, 0.6fr, 0.6fr),
    ("虚拟机名称", "所在主机", "数据存储", "占用容量", "关机时长"),
    data.appendix.powered_off_vms.map(item => (item.name, item.host, item.datastores,
      item.committed_text, field("", item.off_days, suffix: " 天"))))
]
#if data.appendix.snapshot_vms.len() > 0 [
  #v(5mm)
  #page-title("D", "附录 D · 虚拟机快照明细")
  #record-table("虚拟机快照明细", "snapshots", (1.5fr, 0.7fr, 1.8fr, 1.5fr, 0.6fr, 0.4fr),
    ("虚拟机名称", "所在集群", "快照名称", "创建时间", "最长快照时长", "链深度"),
    data.appendix.snapshot_vms.map(item => (item.name, item.cluster, item.snapshot_names, item.snapshot_created,
      field("", item.age_days, suffix: " 天"), field("", item.chain_depth))))
]
#if data.appendix.local_datastore_vms.len() > 0 [
  #v(5mm)
  #page-title("E", "附录 E · 虚拟机磁盘存放在本地存储")
  #record-table("本地存储虚拟机明细", "local-storage", (1.7fr, 0.8fr, 1.3fr, 0.6fr),
    ("虚拟机名称", "所在主机", "本地数据存储", "占用容量"),
    data.appendix.local_datastore_vms.map(item => (item.name, item.host, item.datastores, item.committed_text)))
]
]

]
#if data.product_report != none [
  #let report = data.product_report
  #if not data.has_vcenter [
    #integration-overview(report)
  ] else [
    #v(4mm)
    #page-title("P", "综合巡检产品专项", subtitle: report.scope)
    #par[VC／vSAN 原始等级与历史结论保持原口径。#report.summary]
    #for limitation in report.limitations [#par[#limitation]]
  ]
  #par[#report.deduplication]
  #if report.conflicts.len() > 0 [#par[本次存在 #report.conflicts.len() 组差异记录，全部保留，需核查。]]
  #for (module_index, module) in report.sections.enumerate() [
    #v(4mm)
    #page-title(module.product_name, module.product_name + " 专项 " + module.name)
    #par[#join-fields((field("目标：", module.address), field("版本：", module.version), field("Build：", module.build)))]
    #par[采集时间说明：#module.time；逐来源时间见工程证据。]
    #par[#module.security]
    #let body = module.body
    #par[#body.conclusion]
    #if body.empty_business_text != "" [#par[#body.empty_business_text]]
    #for (table_index, item) in body.tables.enumerate() [
      #v(2mm)
      #record-table(module.product_name + " " + item.title, "product-body-" + str(module_index) + "-" + str(table_index),
        item.weights.map(weight => weight * 1fr), item.columns, item.rows, split-cells: true)
    ]
  ]
  #heading(level: 2, numbering: none)[统一检查限制与工程证据]
  #for item in report.constraints [#par[#strong(item.title)：#item.text]]
  #par[工程附件：#report.evidence_filename。正文 E 编号对应附件 record_index；完整原始字段、内部标识、取数来源及精确采集时间均在附件中保留。]
]
