#let data = json("payload.json")

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

#set page(
  paper: "a4",
  flipped: true,
  margin: (left: 10mm, right: 10mm, top: 15mm, bottom: 13mm),
  fill: white,
  header: context [
    #grid(columns: (1fr, 1fr),
      text(size: 7.5pt, weight: "semibold", fill: navy)[#data.customer_name · 虚拟化巡检报告],
      align(right)[#text(size: 7pt, fill: muted)[巡检日期：#data.report_date]],
    )
    #v(2pt)
    #line(length: 100%, stroke: 0.6pt + border)
  ],
  footer: context [
    #line(length: 100%, stroke: 0.5pt + border)
    #v(2pt)
    #grid(columns: (1fr, 1fr),
      text(size: 6.5pt, fill: muted)[采集日期：#data.capture_date],
      align(right)[#text(size: 6.5pt, fill: muted)[第 #counter(page).display("1 / 1", both: true) 页]],
    )
  ],
)
#set text(font: ("Microsoft YaHei", "SimSun"), size: 7.5pt, fill: ink)
#set par(leading: 1.05em, spacing: 0pt)
#set table(inset: (x: 3pt, y: 2pt), stroke: (x: none, y: 0.45pt + border))

#let pct(value) = if value == none { "未采集" } else { str(calc.round(value * 10) / 10) + "%" }
#let num(value) = if value == none { "未采集" } else { str(value) }
#let priority-color(level) = blue
#let priority-fill(level) = surface
#let header-cell(value) = block(width: 100%, fill: navy, inset: (x: 4pt, y: 5pt), align(center)[#text(size: 7pt, weight: "bold", fill: white)[#value]])
#let body-cell(value) = block(width: 100%, fill: surface, inset: (x: 4pt, y: 10pt), text(size: 7pt, fill: ink)[#value])
#let compact-cell(value) = block(width: 100%, fill: surface, inset: (x: 3pt, y: 4pt), text(size: 6.2pt, fill: ink)[#value])
#let story(value) = block(width: 100%, fill: rgb("#D5E3EF"), stroke: (left: 2pt + blue), inset: 7pt, radius: 3pt)[
  #text(size: 7.5pt, weight: "semibold", fill: navy)[本页解读]
  #v(2pt)
  #text(size: 8pt, fill: ink)[#value]
]
#let page-title(number, title, subtitle: none) = {
  grid(columns: (12mm, 1fr), gutter: 2.5mm, align: (left, horizon),
    block(width: 10mm, fill: navy, inset: 4pt, radius: 2pt, align(center)[#text(size: 11pt, weight: "bold", fill: white)[#number]]),
    stack(dir: ttb, spacing: 3pt,
      text(size: 15pt, weight: "bold", fill: navy)[#title],
      if subtitle != none { text(size: 7pt, fill: muted)[#subtitle] },
    ),
  )
  v(3.5mm)
}
#let metric(label, value, detail: none, accent: blue) = block(width: 100%, fill: surface, stroke: 0.5pt + border, inset: 9pt, radius: 3pt)[
  #text(size: 6.5pt, fill: muted)[#label]
  #linebreak()
  #text(size: 17pt, weight: "bold", fill: accent)[#value]
  #if detail != none [#linebreak() #text(size: 6.5pt, fill: muted)[#detail]]
]
#let bar(value, color: blue, height: 4mm, show-threshold: false) = {
  if value == none { block(width: 100%, height: height, fill: surface-2, radius: 2pt)[#text(size: 6pt, fill: muted)[未采集]] }
  else {
    let bounded = calc.min(calc.max(value, 0), 100)
    block(width: 100%, height: height, fill: surface-2, radius: 2pt)[
      #if bounded > 0 [#place(top + left, rect(width: bounded * 1%, height: height, fill: color, radius: 2pt))]
      #if show-threshold [#place(top + left, dx: 80%, rect(width: 1pt, height: height, fill: navy))]
    ]
  }
}
#let allocation-bar(value) = {
  if value == none { block(width: 100%, height: 5mm, fill: surface-2, radius: 2pt)[#text(size: 6pt, fill: muted)[未采集]] }
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
#let result-strip(counts) = {
  let total = calc.max(counts.passed + counts.failed + counts.unavailable + counts.not_applicable + counts.error, 1)
  grid(columns: (1fr, 1fr, 1fr, 1fr, 1fr), gutter: 1.5mm,
    metric("通过", str(counts.passed), accent: green),
    metric("发现", str(counts.failed), accent: red),
    metric("不可用", str(counts.unavailable), accent: amber),
    metric("不适用", str(counts.not_applicable), accent: muted),
    metric("错误", str(counts.error), accent: red),
  )
  v(2mm)
  block(width: 100%, height: 5mm, fill: surface-2, radius: 2pt)[
    #place(top + left, rect(width: counts.passed / total * 100%, height: 5mm, fill: green, radius: 2pt))
    #place(top + left, dx: counts.passed / total * 100%, rect(width: counts.failed / total * 100%, height: 5mm, fill: red))
    #place(top + left, dx: (counts.passed + counts.failed) / total * 100%, rect(width: counts.unavailable / total * 100%, height: 5mm, fill: amber))
    #place(top + left, dx: (counts.passed + counts.failed + counts.unavailable) / total * 100%, rect(width: counts.not_applicable / total * 100%, height: 5mm, fill: muted))
  ]
}
#let compact-row(left, right, color: blue) = block(width: 100%, fill: surface, inset: (x: 5pt, y: 3pt), radius: 2pt)[
  #grid(columns: (1fr, auto), gutter: 4mm,
    text(size: 7pt, fill: ink)[#left],
    text(size: 7pt, weight: "bold", fill: color)[#right],
  )
]
#let priority-bar(level, count, total) = block(fill: priority-fill(level), inset: 9pt, radius: 3pt)[
  #let share = count * 100 / calc.max(total, 1)
  #grid(columns: (auto, 1fr, auto), gutter: 2mm,
    text(size: 8pt, weight: "bold", fill: priority-color(level))[#level],
    block(width: 100%, height: 5mm, fill: white, radius: 2pt)[
      #if count > 0 [#rect(width: share * 1%, height: 5mm, fill: priority-color(level), radius: 2pt)]
    ],
    text(size: 8pt, weight: "bold")[#count 项],
  )
]
#let disk-group-card(group) = block(fill: surface, inset: 5pt, radius: 3pt)[
  #text(size: 7pt, weight: "bold", fill: navy)[#group.host · #group.name]
  #v(1mm)
  #grid(columns: (1fr, 1fr), gutter: 1mm,
    body-cell("缓存盘 " + str(group.cache)), body-cell("容量盘 " + str(group.capacity)),
  )
  #text(size: 6pt, fill: muted)[健康状态正常 #group.healthy/#group.disks.len() 块]
]
#let action-card(item, optimization: false) = {
  let color = blue
  let fill-color = surface
  let label = if optimization { "P4" } else { item.level }
  block(fill: fill-color, stroke: 0.5pt + border, inset: 7pt, radius: 3pt)[
    #grid(columns: (auto, 1fr, auto), gutter: 2mm,
      block(fill: color, inset: (x: 5pt, y: 2pt), radius: 2pt, text(size: 7pt, weight: "bold", fill: white)[#label]),
      text(size: 8pt, weight: "bold", fill: navy)[#item.title],
      text(size: 7.2pt, weight: "bold")[#item.count_label],
    )
    #text(size: 6.7pt)[影响：#item.impact]
    #text(size: 6.5pt)[步骤：#item.steps.join("；")]
    #text(size: 6.2pt, fill: muted)[责任：#item.owner · 工作量：#item.effort · 维护窗口：#if item.maintenance_window_required [需要] else [不要求] · 复核：#item.verification · #item.rule_id]
  ]
}
#let allocation-cell(value) = stack(dir: ttb, spacing: 0.5mm,
  text(size: 5.8pt, weight: "semibold")[#pct(value)],
  allocation-bar(value),
)
#let top5-row(item, value) = block(width: 100%, inset: (bottom: 8pt))[
  #stack(dir: ttb, spacing: 1.5mm,
    grid(columns: (1fr, auto), gutter: 1mm, align: horizon,
      text(size: 6.2pt, weight: "semibold")[#item.name],
      text(size: 6.2pt, weight: "bold")[#value],
    ),
    grid(columns: (1fr, auto), gutter: 1mm, align: horizon,
      text(size: 5.8pt, fill: muted)[主机 #item.host],
      text(size: 5.8pt, fill: muted)[占比 #pct(item.host_share_pct)],
    ),
    v(1.5mm),
    bar(item.bar_pct, color: blue, height: 4mm),
  )
]
#let datastore-name(value) = block(inset: (bottom: 2pt), text(size: 8pt, weight: "semibold", font: ("Consolas", "Microsoft YaHei", "SimSun"))[#raw(value)])

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
      text(fill: rgb("#BBD4E9"))[平台版本], text(weight: "semibold", fill: white)[vCenter #data.environment.vcenter_version · Build #data.environment.vcenter_build],
      text(fill: rgb("#BBD4E9"))[报告编号], text(size: 6pt, fill: white)[#data.run_id],
    )
    #v(6mm)
    #block(fill: rgb("#234C72"), inset: 8pt, radius: 3pt)[
      #text(size: 8pt, weight: "bold", fill: white)[执行摘要]
      #v(2mm)
      #text(size: 8pt, fill: white)[#data.narratives.executive]
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
#grid(columns: (1fr, 1fr, 1fr), gutter: 3mm,
  metric("需处理事项", str(data.problem_count), detail: "P1 " + str(data.risk_counts.P1) + " · P2 " + str(data.risk_counts.P2) + " · P3 " + str(data.risk_counts.P3), accent: blue),
  metric("影响对象", str(data.issue_object_count), detail: "去重前按规则汇总", accent: blue),
  metric("优化建议", str(data.optimization_count), detail: "独立于需处理事项", accent: blue),
)
#v(3mm)
#grid(columns: (1fr, 1fr, 1fr), gutter: 3mm,
  priority-bar("P1", data.risk_counts.P1, data.problem_count),
  priority-bar("P2", data.risk_counts.P2, data.problem_count),
  priority-bar("P3", data.risk_counts.P3, data.problem_count),
)
#v(2mm)
#grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
  metric("vSAN 容量使用", data.vsan.used_percent_text, detail: "总量 " + data.vsan.total_display + " GB", accent: blue),
  metric("vSAN 物理盘", num(data.vsan.healthy_disks) + "/" + num(data.vsan.disk_count), detail: "正常 / 总数", accent: blue),
  metric("vSAN 重同步", if data.vsan.no_resync { "0 对象 · 0 B" } else { data.vsan.resync_objects_text + " 对象" }, accent: blue),
)
#v(1mm)
#compact-row("检查覆盖", str(data.scope.visible_rule_count) + " 条规则 · " + str(data.scope.visible_result_total) + " 条结果 · " + str(data.filtered_finding_count) + " 条发现", color: blue)

#pagebreak()

// 02 - Scope, method, and result coverage
#page-title("02", "巡检范围与方法", subtitle: "展示的规则结果按本报告范围过滤后汇总；不可用与不适用不作为通过")
#block(width: 100%, fill: surface, stroke: 0.5pt + border, inset: 6pt, radius: 3pt)[
  #text(size: 9pt, weight: "bold", fill: navy)[结果状态分布 · 可展示规则 #data.scope.visible_rule_count 条 · 可展示结果 #data.scope.visible_result_total 条]
  #v(1mm)
  #result-strip(data.scope.visible_result_counts)
]
#v(1.5mm)
#block(width: 100%, fill: navy, inset: 6pt, radius: 3pt)[
  #text(size: 7.2pt, fill: white)[本次检查 #data.scope.checked_object_total 个对象。不可用项表示证据不足，应结合采集权限与接口返回复核；不适用项按对象类型或配置条件排除。]
  #linebreak()
  #text(size: 7pt, fill: rgb("#DCEAF6"))[本报告不含 VMware Tools 与 Syslog 相关检查项。]
]
#v(2mm)
#text(size: 9pt, weight: "bold", fill: navy)[不可用结果：原因与影响范围]
#grid(columns: (0.14fr, 0.35fr, 0.25fr, 1.1fr), gutter: 1pt,
  header-cell("规则"), header-cell("检查项"), header-cell("缺失数量"), header-cell("本次未能确认的原因"),
)
#for item in data.scope.unavailable_rows {
  grid(columns: (0.14fr, 0.35fr, 0.25fr, 1.1fr), gutter: 1pt,
    body-cell(item.rule_id), body-cell(item.name), body-cell(str(item.count)), body-cell(item.reason),
  )
}
#v(2mm)
#text(size: 9pt, weight: "bold", fill: navy)[不适用结果：检查项与对象数]
#grid(columns: (0.16fr, 0.5fr, 0.3fr, 0.85fr), gutter: 1pt,
  header-cell("规则"), header-cell("检查项"), header-cell("对象数"), header-cell("适用性说明"),
)
#for item in data.scope.not_applicable_rows {
  grid(columns: (0.16fr, 0.5fr, 0.3fr, 0.85fr), gutter: 1pt,
    body-cell(item.rule_id), body-cell(item.name), body-cell(str(item.count) + " · " + item.object_type), body-cell(item.reason),
  )
}
#v(2mm)
#story(data.narratives.scope)

#pagebreak()

// 03 - Overview and finding distribution
#page-title("03", "环境总览与问题分布", subtitle: "资产规模与过滤后的需处理事项分布")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("集群", str(data.counts.clusters) + " 个"),
  metric("主机", str(data.counts.hosts) + " 台"),
  metric("虚拟机", str(data.counts.vms) + " 台"),
  metric("存储", str(data.counts.datastores) + " 个"),
)
#v(3mm)
#grid(columns: (0.8fr, 1.2fr), gutter: 4mm, align: top,
  stack(dir: ttb, spacing: 3mm,
  block(width: 100%, fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 9pt, weight: "bold", fill: navy)[需处理事项分布]
    #v(3mm)
    #for level in ("P1", "P2", "P3") {
      let value = data.risk_counts.at(level)
      let total = calc.max(data.problem_count, 1)
      grid(columns: (12mm, 1fr, 16mm), gutter: 2mm, align: horizon,
        text(weight: "bold", fill: priority-color(level))[#level],
        block(width: 100%, height: 7mm, fill: surface-2, radius: 2pt)[
          #if value > 0 [#place(top + left, rect(width: value / total * 100%, height: 7mm, fill: priority-color(level), radius: 2pt))]
        ],
        align(right)[#text(size: 9pt, weight: "bold")[#value 项]],
      )
      v(2mm)
    }
    #text(size: 6.5pt, fill: muted)[优先级依据规则输出；受影响对象可能跨规则重复，不作为去重资产数。]
  ],
  block(width: 100%, fill: navy, inset: 7pt, radius: 3pt)[
    #text(size: 8pt, weight: "bold", fill: white)[虚拟机运行状态]
    #v(1mm)
    #text(size: 13pt, weight: "bold", fill: white)[开机 #data.counts.powered_on · 关机 #data.counts.powered_off · 挂起 #data.counts.suspended]
    #v(2mm)
    #bar(data.counts.powered_on * 100 / calc.max(data.counts.vms, 1), color: green, height: 5mm)
  ],
  block(width: 100%, fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 8pt, weight: "bold", fill: navy)[快照对象]
    #v(1mm)
    #text(size: 13pt, weight: "bold", fill: blue)[#data.counts.snapshot_vms 台]
    #text(size: 6.5pt, fill: muted)[此处按存在快照的虚拟机数统计，不等同于快照链深度。]
  ],
  ),
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 9pt, weight: "bold", fill: navy)[按对象类型统计发现]
    #v(2mm)
    #for item in data.findings_by_object_type {
      let ratio = item.count * 100 / calc.max(data.filtered_finding_count, 1)
      grid(columns: (0.65fr, 1.7fr, 14mm), gutter: 2mm, align: horizon,
        text(size: 7pt, weight: "semibold")[#item.name],
        block(width: 100%, height: 5mm, fill: surface-2, radius: 2pt)[
          #place(top + left, rect(width: ratio * 1%, height: 5mm, fill: blue, radius: 2pt))
        ],
        align(right)[#text(weight: "bold")[#item.count]],
      )
      v(1.2mm)
    }
    #v(2mm)
    #grid(columns: (1fr, 1fr), gutter: 2mm,
      metric("过滤后 finding", str(data.filtered_finding_count)),
      metric("优化建议类别", str(data.optimization_count)),
    )
    #v(2mm)
    #text(size: 8pt, weight: "bold", fill: navy)[需处理类别 · 受影响对象数]
    #v(1.5mm)
    #v(1.5mm)
    #for item in data.category_rows.slice(0, calc.min(data.category_rows.len(), 9)) {
      let width = item.objects * 100 / calc.max(data.max_issue_category_objects, 1)
      grid(columns: (1.1fr, 0.8fr, 14mm), gutter: 1mm, align: horizon,
        text(size: 6.2pt, fill: ink)[#item.title],
        block(width: 100%, height: 4.5mm, fill: white, radius: 1pt)[
          #if width > 0 [#rect(width: width * 1%, height: 4.5mm, fill: priority-color(item.level), radius: 1pt)]
        ],
        align(right)[#text(size: 6pt, weight: "bold")[#item.objects]],
      )
      v(1.3mm)
    }
  ],
)
#v(3mm)
#story(data.narratives.overview)

#pagebreak()

// 04 - Cluster configuration
#page-title("04", "集群保护与配置", subtitle: "展示 HA、准入控制、心跳、隔离响应、DRS、EVC 与 vMotion 的采集状态")
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
      text(size: 9pt, weight: "bold", fill: navy)[#cluster.name],
      text(size: 7pt)[#cluster.kind · #cluster.host_count 台主机 · #cluster.vm_count 台 VM],
      text(size: 7pt)[HA #if cluster.ha_enabled == true [启用] else if cluster.ha_enabled == false [未启用] else [未采集]],
      text(size: 7pt)[DRS #if cluster.drs_enabled == true [启用] else if cluster.drs_enabled == false [未启用] else [未采集]],
    )
    #v(2mm)
    #grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
      body-cell("准入控制：" + cluster.admission_control),
      body-cell("心跳数据存储：" + cluster.heartbeat_summary),
      body-cell("隔离响应：" + cluster.isolation_response),
      body-cell("DRS 模式：" + cluster.drs_behavior),
      body-cell("EVC：" + cluster.evc_enabled + " · " + cluster.evc_mode),
      body-cell("vMotion：" + num(cluster.vmotion_enabled_hosts) + "/" + str(cluster.host_count)),
      body-cell("CPU 型号数：" + num(cluster.cpu_model_count)),
      body-cell("内存容量差异：" + pct(cluster.memory_skew_pct)),
    )
    #v(2mm)
    #grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
      block(fill: surface-2, inset: 4pt, radius: 2pt)[
        #text(size: 6pt, weight: "semibold")[集群 CPU 使用率 · #pct(cluster.cpu_usage_pct)]
        #v(0.5mm)
        #bar(cluster.cpu_usage_pct, color: blue, height: 4mm)
      ],
      block(fill: surface-2, inset: 4pt, radius: 2pt)[
        #text(size: 6pt, weight: "semibold")[主机内存容量差异 · #pct(cluster.memory_skew_pct)]
        #v(0.5mm)
        #bar(cluster.memory_skew_pct, color: blue, height: 4mm)
      ],
      block(fill: surface-2, inset: 4pt, radius: 2pt)[
        #text(size: 6pt, weight: "semibold")[主机 · #cluster.host_count 台]
        #text(size: 5.8pt, fill: muted)[#cluster.host_names]
        #text(size: 5.8pt, fill: muted)[CPU 型号：#cluster.cpu_models]
      ],
    )
    #if cluster.drs_disabled_rules != "" [#v(1mm) #text(size: 6.5pt, fill: muted)[DRS 禁用规则：#cluster.drs_disabled_rules]]
    #if cluster.vmotion_missing_hosts != "" [#v(1mm) #text(size: 6.5pt, fill: amber)[未启用 vMotion 主机：#cluster.vmotion_missing_hosts]]
    #if cluster.maintenance_hosts != "" [#v(1mm) #text(size: 6.5pt, fill: muted)[维护模式主机：#cluster.maintenance_hosts]]
  ]
  v(3.5mm)
}
#grid(columns: (1fr, 1fr), gutter: 3mm,
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 8pt, weight: "bold", fill: navy)[HA 启用覆盖]
    #v(2mm)
    #bar(data.ha_chart.value * 100 / calc.max(data.ha_chart.total, 1), color: blue, height: 6mm)
    #text(size: 6.5pt, fill: muted)[#data.ha_chart.note]
  ],
  block(fill: surface, inset: 7pt, radius: 3pt)[
    #text(size: 8pt, weight: "bold", fill: navy)[DRS 启用覆盖]
    #v(2mm)
    #bar(data.drs_chart.value * 100 / calc.max(data.drs_chart.total, 1), color: blue, height: 6mm)
    #text(size: 6.5pt, fill: muted)[#data.drs_chart.note]
  ],
)
#v(3mm)
#story(data.narratives.clusters)

#pagebreak()

// 05 - Host status and current utilization
#page-title("05", "主机状态与资源使用", subtitle: "CPU/内存为采集时点值；80% 参考线用于定位，不代替持续性能分析")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("主机", str(data.counts.hosts), accent: blue),
  metric("已连接", str(data.connected_host_count) + "/" + str(data.counts.hosts), accent: green),
  metric("硬件异常", str(data.hardware_issue_total), detail: "未采集不按正常计", accent: if data.hardware_issue_total > 0 { red } else { blue }),
  metric("电源策略", "已采集", detail: "逐主机列示", accent: blue),
)
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[主机 CPU 使用率]
    #for host in data.host_details {
      grid(columns: (0.55fr, 1fr, 12mm), gutter: 1mm, align: horizon,
        text(size: 6pt)[#host.name], bar(host.cpu_pct, color: blue, height: 7mm, show-threshold: true), align(right)[#pct(host.cpu_pct)],
      )
      v(2.5mm)
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[主机内存使用率]
    #for host in data.host_details {
      grid(columns: (0.55fr, 1fr, 12mm), gutter: 1mm, align: horizon,
        text(size: 6pt)[#host.name], bar(host.memory_pct, color: blue, height: 7mm, show-threshold: true), align(right)[#pct(host.memory_pct)],
      )
      v(2.5mm)
    }
  ],
)
#v(0.5mm)
#text(size: 5.8pt, fill: muted)[两图竖线均为 80% 参考线。]
#v(1.5mm)
#text(size: 7.5pt, weight: "bold", fill: navy)[主机与硬件明细]
#grid(columns: (0.85fr, 0.72fr, 0.62fr, 0.55fr, 0.65fr, 0.9fr, 0.72fr), gutter: 0.5pt,
  header-cell("ESXi 主机"), header-cell("集群"), header-cell("连接"), header-cell("CPU 核心"), header-cell("内存 GB"), header-cell("硬件异常"), header-cell("电源策略"),
)
#for host in data.host_details {
  grid(columns: (0.85fr, 0.72fr, 0.62fr, 0.55fr, 0.65fr, 0.9fr, 0.72fr), gutter: 0.5pt,
    body-cell(host.name), body-cell(host.cluster), body-cell(host.connection), body-cell(num(host.cpu_cores)), body-cell(num(host.memory_capacity_gb)),
    body-cell(if host.hardware_issue_count == none { "未采集" } else { str(host.hardware_issue_count) + " 项" }), body-cell(host.power_policy),
  )
}
#for host in data.host_details {
  if host.hardware_issue_summary != "" [#text(size: 6pt, fill: red)[#host.name：#host.hardware_issue_summary]]
}
#v(2mm)
#story(data.narratives.hosts)

#pagebreak()

// 06 - Resource allocation and Top 5
#page-title("06", "资源分配与 Top 5", subtitle: "资源分配使用主机配置容量；Top 5 展示 vCPU 数和同主机 VMDK 配置容量")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("物理 CPU 核心", num(data.counts.cpu_cores), accent: blue),
  metric("物理内存", num(data.counts.memory_total_gb) + " GB", accent: blue),
  metric("超配主机", str(data.overcommit_host_count) + "/" + str(data.counts.hosts), detail: "主机级资源分配标记", accent: if data.overcommit_host_count > 0 { amber } else { blue }),
  metric("Top 5 数据", str(data.top_vcpu.len() + data.top_capacity.len()) + " 项", accent: blue),
)
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[主机 vCPU:pCPU]
    #for host in data.host_details {
      grid(columns: (0.95fr, 1.05fr, 12mm), gutter: 1mm, align: horizon,
        text(size: 5.8pt)[#host.name · #num(host.allocated_vcpu)/#num(host.cpu_cores)],
        bar(if host.vcpu_pcpu_ratio == none { none } else { calc.min(host.vcpu_pcpu_ratio * 10, 100) }, color: if host.overcommit == true { amber } else { blue }, height: 5mm),
        align(right)[#num(host.vcpu_pcpu_ratio):1],
      )
      v(1.5mm)
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[主机内存分配 · 100% 容量线]
    #for host in data.host_details {
      grid(columns: (0.95fr, 1.05fr, 12mm), gutter: 1mm, align: horizon,
        text(size: 5.8pt)[#host.name · #num(host.memory_allocated_gb)/#num(host.memory_capacity_gb) GB],
        allocation-bar(host.memory_allocation_pct),
        align(right)[#pct(host.memory_allocation_pct)],
      )
      v(1.5mm)
    }
  ],
)
#v(0.5mm)
#text(size: 5.8pt, fill: muted)[橙色表示主机级资源超配或内存分配超过 100%；内存条按 0-125% 缩放，竖线表示 100%。]
#v(1.5mm)
#grid(columns: (1fr, 1fr), gutter: 2mm,
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[vCPU 配置 Top 5 · 占同主机配置总量]
    #for item in data.top_vcpu {
      top5-row(item, item.display)
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 5pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[VMDK 配置容量 Top 5 · 占同主机已采集容量]
    #for item in data.top_capacity {
      top5-row(item, item.display)
    }
  ],
)
#v(1.5mm)
#story(data.narratives.capacity)

#pagebreak()

// 07 - Datastore capacity and vSAN summary
#page-title("07", "数据存储容量与 vSAN 概况", subtitle: "按使用率排序展示数据存储；vSAN 正文给出容量、对象、磁盘组与重同步结论")
#grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
  metric("数据存储", str(data.counts.datastores), accent: blue),
  metric("最高存储使用率", data.highest_datastore_usage, accent: if data.highest_datastore_pct >= 80 { red } else { blue }),
  metric("vSAN 容量使用率", data.vsan.used_percent_text, accent: blue),
)
#v(1.5mm)
#text(size: 7.5pt, weight: "bold", fill: navy)[数据存储使用率 · 80% 参考线]
#for store in data.datastores {
  grid(columns: (0.85fr, 0.3fr, 1.75fr, 0.36fr, 0.5fr), gutter: 0.5pt, align: horizon,
    datastore-name(store.name),
    text(size: 6.2pt)[#store.type],
    text(size: 6.2pt)[已用 #store.used_text · 可用 #store.free_text · 总量 #store.total_text],
    align(right)[#text(size: 6pt, weight: "bold")[#store.usage_text]],
    text(size: 5.8pt, fill: muted)[#store.clusters.join("、")],
  )
  bar(store.usage, color: if store.usage != none and store.usage >= 80 { red } else if store.usage != none and store.usage >= 75 { amber } else { blue }, height: 3.5mm, show-threshold: true)
  v(1mm)
}
#v(1mm)
#if data.vsan.enabled {
  grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 1.5mm,
    metric("vSAN 总容量", data.vsan.total_display + " GB", accent: blue),
    metric("vSAN 已用", data.vsan.used_display + " GB · " + data.vsan.used_percent_text, accent: blue),
    metric("对象 / VMDK", num(data.vsan.object_count) + " / " + num(data.vsan.vmdk_count), accent: blue),
    metric("物理盘正常", num(data.vsan.healthy_disks) + "/" + num(data.vsan.disk_count), accent: if data.vsan.disk_count == data.vsan.healthy_disks { green } else { amber }),
  )
  v(1mm)
  compact-row("vSAN 磁盘组与盘型", num(data.vsan.disk_group_count) + " 组 · 缓存 " + num(data.vsan.cache_disk_count) + " 块 · 容量 " + num(data.vsan.capacity_disk_count) + " 块", color: blue)
  compact-row("Resync 状态", data.vsan.resync_summary_text, color: if data.vsan.no_resync { green } else { amber })
  v(0.8mm)
  grid(columns: (1fr, 1fr, 1fr), gutter: 1.5mm,
    ..data.disk_groups.map(group => disk-group-card(group)),
  )
  if data.vsan.storage_policy_failure [#v(1mm) #block(fill: pale-amber, inset: 4pt, radius: 2pt)[#text(size: 6pt, weight: "semibold", fill: amber)[存储策略查询：#data.vsan.storage_policy_vm_counts.api_error 台虚拟机 API 错误、#data.vsan.storage_policy_vm_counts.collected 台返回结果；错误对象不能据此判断合规。]]]
} else {
  block(fill: surface, inset: 8pt, radius: 3pt)[#text(size: 7pt, fill: muted)[本次没有采集到可确认的 vSAN 集群数据。]]
}
#v(1mm)
#story(data.narratives.storage_vsan)

#pagebreak()

// 08 - Network, security, and certificates
#page-title("08", "网络、安全基线与证书", subtitle: "VMkernel、物理链路、主机安全设置、端口组策略及证书明细")
#grid(columns: (1fr, 1fr, 1fr, 1fr, 1fr), gutter: 1.5mm,
  metric("VMkernel", str(data.network.vmkernel_count), accent: blue),
  metric("上行断链", str(data.network.pnic_down_count) + " 块", detail: str(data.network.pnic_down_host_count) + " 台主机", accent: if data.network.pnic_down_count > 0 { red } else { blue }),
  metric("速率异常", str(data.network.pnic_degraded_count) + " 块", accent: if data.network.pnic_degraded_count > 0 { amber } else { blue }),
  metric("端口组策略项", str(data.security.portgroup_issues), accent: if data.security.portgroup_issues > 0 { amber } else { blue }),
  metric("已连接主机", str(data.connected_host_count) + "/" + str(data.counts.hosts), accent: blue),
)
#v(1.5mm)
#story(data.narratives.network_security)
#v(1.5mm)
#grid(columns: (1.1fr, 0.9fr), gutter: 2mm, align: top,
  block(fill: surface, stroke: 0.5pt + border, inset: 4pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[VMkernel 网络明细 · #data.network.vmkernel_count 项]
    #grid(columns: (0.65fr, 0.34fr, 0.62fr, 0.9fr, 0.64fr, 0.28fr), gutter: 0.5pt,
      header-cell("主机"), header-cell("设备"), header-cell("IP"), header-cell("Network Label"), header-cell("交换机"), header-cell("MTU"),
    )
    #for vmk in data.network.vmkernels {
      grid(columns: (0.65fr, 0.34fr, 0.62fr, 0.9fr, 0.64fr, 0.28fr), gutter: 0.5pt,
        compact-cell(vmk.host), compact-cell(vmk.device), compact-cell(vmk.ip), compact-cell(vmk.label), compact-cell(vmk.switch), compact-cell(vmk.mtu),
      )
    }
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 4pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[物理网卡异常明细 · #data.network.pnic_detail_count 条]
    #grid(columns: (0.55fr, 0.32fr, 0.62fr, 0.62fr, 1fr), gutter: 0.5pt,
      header-cell("主机"), header-cell("设备"), header-cell("上行"), header-cell("实际 / 配置速率"), header-cell("状态依据"),
    )
    #for nic in data.network.pnics {
      grid(columns: (0.55fr, 0.32fr, 0.62fr, 0.62fr, 1fr), gutter: 0.5pt,
        compact-cell(nic.host), compact-cell(nic.device), compact-cell(if nic.uplink { "是" } else { "否" }),
        compact-cell(nic.actual_speed + " / " + nic.configured_speed),
        compact-cell(nic.assessment + "（" + nic.assessment_basis + "）"),
      )
    }
    #v(1mm)
    #text(size: 5.8pt, fill: muted)[链路中断依据主机级 pnic_down_count；速率字段未采集不参与判定。未返回逐接口数据的主机不据此补造正常网卡清单。]
  ],
)
#v(1.5mm)
#grid(columns: (1.05fr, 0.95fr), gutter: 2mm, align: top,
  block(fill: surface, stroke: 0.5pt + border, inset: 4pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[主机安全基线 · #data.counts.hosts 台]
    #grid(columns: (0.62fr, 0.38fr, 0.38fr, 0.35fr, 0.42fr, 0.42fr, 0.55fr), gutter: 0.5pt,
      header-cell("主机"), header-cell("SSH"), header-cell("Shell"), header-cell("NTP"), header-cell("防火墙"), header-cell("Lockdown"), header-cell("端口组项"),
    )
    #for host in data.host_details {
      grid(columns: (0.62fr, 0.38fr, 0.38fr, 0.35fr, 0.42fr, 0.42fr, 0.55fr), gutter: 0.5pt,
        compact-cell(host.name), compact-cell(host.ssh), compact-cell(host.esxi_shell), compact-cell(num(host.ntp_server_count)),
        compact-cell(host.firewall_default_blocked), compact-cell(host.lockdown), compact-cell(num(host.portgroup_security_count)),
      )
    }
    #if data.security.portgroup_details.len() > 0 [
      #v(1mm)
      #text(size: 6.2pt, weight: "semibold", fill: navy)[端口组策略异常：]
      #grid(columns: (0.48fr, 0.52fr, 0.8fr, 0.55fr, 0.62fr), gutter: 0.5pt,
        header-cell("主机"), header-cell("交换机"), header-cell("端口组"), header-cell("策略项"), header-cell("当前 → 建议"),
      )
      #for issue in data.security.portgroup_details {
        grid(columns: (0.48fr, 0.52fr, 0.8fr, 0.55fr, 0.62fr), gutter: 0.5pt,
          compact-cell(issue.host), compact-cell(issue.switch), compact-cell(issue.portgroup), compact-cell(issue.setting), compact-cell(issue.current + " → " + issue.recommended),
        )
      }
    ]
  ],
  block(fill: surface, stroke: 0.5pt + border, inset: 4pt, radius: 3pt)[
    #text(size: 7.5pt, weight: "bold", fill: navy)[证书到期与许可]
    #grid(columns: (0.58fr, 0.6fr, 0.4fr, 0.42fr), gutter: 0.5pt,
      header-cell("对象"), header-cell("到期日"), header-cell("剩余天数"), header-cell("状态"),
    )
    #grid(columns: (0.58fr, 0.6fr, 0.4fr, 0.42fr), gutter: 0.5pt,
      compact-cell("vCenter"), compact-cell(data.certificates.vcenter.expiry), compact-cell(num(data.certificates.vcenter.remaining_days)), compact-cell(data.certificates.vcenter.status),
    )
    #for cert in data.certificates.hosts {
      grid(columns: (0.58fr, 0.6fr, 0.4fr, 0.42fr), gutter: 0.5pt,
        compact-cell(cert.host), compact-cell(cert.expiry), compact-cell(num(cert.remaining_days)), compact-cell(cert.status),
      )
    }
    #v(1mm)
    #text(size: 5.8pt, fill: muted)[#data.certificates.summary]
    #text(size: 5.8pt, fill: muted)[许可：#data.certificates.licenses.join("；")]
  ],
)

#pagebreak()

// 09 - Actionable findings
#page-title("09", "需处理事项与建议", subtitle: "按处置优先级完整列示全部 P1-P3 类别，不截断整改步骤")
#grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 2mm,
  metric("需处理类别", str(data.problem_count)),
  metric("P1", str(data.risk_counts.P1), detail: str(data.affected_counts.P1) + " 个受影响对象", accent: blue),
  metric("P2", str(data.risk_counts.P2), detail: str(data.affected_counts.P2) + " 个受影响对象", accent: blue),
  metric("P3", str(data.risk_counts.P3), detail: str(data.affected_counts.P3) + " 个受影响对象", accent: blue),
)
#v(2mm)
#story(data.narratives.remediation)
#v(2mm)
#for item in data.problems {
  action-card(item)
  v(0.8mm)
}

#pagebreak()

// 10 - Optimization plan and vSAN appendix
#page-title("10", "优化建议与附录", subtitle: "P4 优化建议单独呈现；附录 A 列出 vSAN 逐盘设备标识")
#grid(columns: (1fr, 1fr, 1fr), gutter: 2mm,
  metric("优化建议类别", str(data.optimization_count), accent: blue),
  metric("涉及对象", str(data.optimization_object_count), detail: "可能存在跨类别重复", accent: blue),
  metric("需处理事项", str(data.problem_count), detail: "另见第 9 页", accent: blue),
)
#v(2mm)
#story(data.narratives.optimizations)
#v(2mm)
#grid(columns: (1fr, 1fr), gutter: 2.5mm, align: top,
  [#for item in data.optimizations.slice(0, calc.ceil(data.optimizations.len() / 2)) { action-card(item, optimization: true); v(1mm) }],
  [#for item in data.optimizations.slice(calc.ceil(data.optimizations.len() / 2), data.optimizations.len()) { action-card(item, optimization: true); v(1mm) }],
)
#v(2mm)
#text(size: 8pt, weight: "bold", fill: navy)[附录 A · vSAN 物理盘明细]
#grid(columns: (0.6fr, 0.48fr, 0.42fr, 1.25fr, 0.35fr), gutter: 0.5pt,
  header-cell("主机"), header-cell("磁盘组"), header-cell("角色"), header-cell("设备标识 NAA"), header-cell("状态"),
)
#for disk in data.vsan.disk_details {
  grid(columns: (0.6fr, 0.48fr, 0.42fr, 1.25fr, 0.35fr), gutter: 0.5pt,
    compact-cell(disk.host), compact-cell(disk.group), compact-cell(disk.role), compact-cell(disk.device), compact-cell(disk.health),
  )
}
