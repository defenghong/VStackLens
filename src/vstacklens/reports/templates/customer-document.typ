#let data = json("document.json")
#let visual = data.visual
#let navy = rgb(data.navy)
#let ink = rgb(data.ink)
#let muted = rgb(data.neutral)
#let border = rgb("#B9C8D6")
#let surface = rgb("#E9EEF3")
#let pale-blue = rgb("#EDF3F8")
#let grade-color(level) = rgb(data.colors.at(level))
#set document(title: data.title, author: "VStackLens")
#set page(paper: "a4", flipped: true,
 margin: (left: 10mm, right: 10mm, top: 21mm, bottom: 16mm),
 header: [#grid(columns: (1fr, auto),
  text(size: 10pt, fill: navy, weight: "semibold")[#visual.header_identity],
  text(size: 10pt, fill: muted)[#visual.date_label])
  #v(2pt)#line(length: 100%, stroke: 0.6pt + border)],
 footer: context [#line(length: 100%, stroke: 0.5pt + border)#v(2pt)
  #grid(columns: (1fr, auto),text(size: 10pt, fill: muted)[#visual.date_label],
   text(size: 10pt, fill: muted)[第 #counter(page).display() / #counter(page).final().first() 页])],
)
#set text(font: ("Microsoft YaHei", "SimSun", "Segoe UI Symbol"), size: 11pt, fill: ink)
#let paragraph-gap = 6pt
#set par(leading: 0.95em, spacing: paragraph-gap)
#show heading: set block(above: 4mm, below: 2mm)
#show heading.where(level: 1): set text(size: 16pt, fill: navy, weight: "bold")
#show heading.where(level: 2): set text(size: 13pt, fill: navy, weight: "bold")
#let paragraph(value) = if value != "" { block[#value] }
#let tag(level) = box(inset: (x: 5pt, y: 2pt), stroke: 0.8pt + grade-color(level), radius: 2pt,
 text(weight: "bold", fill: grade-color(level))[#level])
// Reused visual primitives from 7f9653a, with the approved grade palette.
#let page-title(number, title, subtitle: "") = heading(level: 1, numbering: none,
 grid(columns: (12mm, 1fr), gutter: 2.5mm, align: (left, horizon),
  block(width: 10mm, fill: navy, inset: 4pt, radius: 2pt, align(center)[#text(size: 11pt, weight: "bold", fill: white)[#number]]),
  stack(dir: ttb, spacing: 5pt,
   block[#text(size: 15pt, weight: "bold", fill: navy)[#title]],
   if subtitle != "" { block[#text(size: 10.5pt, fill: muted)[#subtitle]] })))
#let story(value) = if value != "" { block(breakable: false, width: 100%, fill: rgb("#D5E3EF"), stroke: (left: 2pt + navy), inset: 7pt, radius: 3pt)[
 #text(size: 11pt, weight: "semibold", fill: navy)[检查解读]
 #linebreak()#text(size: 11pt)[#value]
] }
#let metric(item) = block(width: 100%, fill: surface, stroke: 0.5pt + border, inset: 9pt, radius: 3pt)[
 #text(size: 10pt, fill: muted)[#item.label]#linebreak()
 #text(size: 19pt, weight: "bold", fill: ink)[#item.value]
 #if item.detail != "" [#linebreak()#text(size: 10pt, fill: muted)[#item.detail]]
]
#let metrics(items) = if items.len() > 0 { grid(columns: range(items.len()).map(_ => 1fr), gutter: 3mm, ..items.map(metric)) }
#let table-view(t, continued: false, flow: false) = context {
 let marker = label("table-" + t.id)
 let grid = table(columns: t.weights.map(n => n * 1fr), inset: (x: 5pt, y: 5pt),
  stroke: 0.45pt + border, align: left + top,
  table.header(repeat: true,
   table.cell(colspan: t.headers.len(), fill: pale-blue)[#context {
    let rest = continued or counter(page).get().first() > counter(page).at(marker).first()
    text(size: 11pt, fill: navy, weight: "bold")[#t.title#if rest [（续）]]
   }],
   ..t.headers.map(h => table.cell(fill: navy)[#text(size: 10.5pt, fill: white, weight: "bold")[#h]])),
  ..t.rows.map(row => row.cells.map(value => table.cell(breakable: not flow)[#text(size: 10.5pt)[#value]])).flatten())
 if not flow and t.rows.len() <= 15 and measure(grid, width: 277mm).height <= 173mm {
  block(breakable: false)[#grid#marker]
 } else { [#grid#marker] }
 for note in t.notes { paragraph(note) }
 if "reference" in t and t.reference != "" { paragraph(t.reference) }
}
#let graph-title(g) = [#text(size: 12pt, weight: "bold", fill: navy)[#g.title]#v(2mm)]
#let graph-row(g,row) = [
 #grid(columns:(0.52fr,0.30fr,0.14fr),column-gutter:2mm,align:horizon,
    text(size:10.5pt)[#row.name#if "detail" in row and row.detail!="" [ · #row.detail]],
    block(width:100%,height:3mm,fill:white)[
    #place(left, rect(width: calc.min(100, row.value / g.axis_max * 100) * 1%, height: 3mm,
      fill: if row.value > g.threshold { rgb("#506B84") } else { rgb("#8CA9BF") }))
    #place(left, dx: g.threshold / g.axis_max * 100%, line(start: (0pt,-0.5mm), end: (0pt,3.5mm),stroke:0.8pt+navy))],
    align(right)[#text(size:10.5pt,weight:"semibold")[#row.text]])
 #v(1.2mm)
]
#let graph-axis(g) = grid(columns:(0.52fr,0.30fr,0.14fr),column-gutter:2mm,[],block(width:100%,height:25pt)[#layout(size=>{
   let ticks=g.ticks.sorted(key:t=>t.value)
   let contents=ticks.map(t=>box(text(size:10pt,fill:if t.value==g.threshold {navy} else {muted},weight:if t.value==g.threshold {"bold"} else {"regular"})[#t.text]))
   let widths=contents.map(c=>measure(c).width)
   let previous-end=0pt
   for (i,tick) in ticks.enumerate() {
    let color=if tick.value==g.threshold {navy} else {muted}
    let anchor=size.width*tick.value/g.axis_max
    let x=if i==0 {0pt} else if i==ticks.len() - 1 {size.width - widths.at(i)} else {
     calc.max(previous-end+4pt,calc.min(anchor - widths.at(i)/2,size.width - widths.last() - widths.at(i) - 4pt))}
    let end=if i==0 or i==ticks.len() - 1 {anchor} else {x+widths.at(i)/2}
    place(left,dx:anchor,line(start:(0pt,-1pt),end:(end - anchor,3pt),stroke:0.6pt+color))
    place(left,dy:6pt,dx:x)[#contents.at(i)]
    previous-end=x+widths.at(i)
   }
 })],[])
#let graph-groups(rows) = {
 let groups=rows.chunks(3)
 if groups.len() > 1 and groups.last().len() < 3 {
  let tail=groups.pop()
  let previous=groups.pop()
  groups.push(previous+tail)
 }
 groups
}
#let graph-whole(g) = block(breakable:false,width:100%,fill:surface,inset:8pt,radius:3pt)[
 #graph-title(g)
 #if "equal_text" in g and g.equal_text != "" {paragraph(g.equal_text)} else {
  for row in g.series {graph-row(g,row)}
  graph-axis(g)
 }
 #if g.more != "" {paragraph(g.more)}
]
#let graph(g) = layout(size=>{
 let whole=graph-whole(g)
 let comparable=not ("equal_text" in g and g.equal_text != "")
 if comparable and g.series.len() >= 6 and measure(whole,width:size.width).height > 173mm / 2 {
  block(breakable:true,width:100%,fill:surface,inset:8pt,radius:3pt)[
   #table(columns:(1fr,),inset:0pt,stroke:none,
    table.header(repeat:true,table.cell()[#graph-title(g)]),
    ..graph-groups(g.series).map(rows=>table.cell(breakable:false,inset:(x:0pt,top:paragraph-gap,bottom:0pt))[
     #for row in rows {graph-row(g,row)}
    ]),
    table.footer(repeat:true,table.cell(inset:(x:0pt,top:paragraph-gap,bottom:0pt))[
     #graph-axis(g)
     #if g.more != "" {paragraph(g.more)}
    ]))
  ]
 } else {whole}
})
#let problem-head(p) = [
 #heading(level:2,block(stroke:(left:2pt+grade-color(p.level)),inset:(left:7pt))[
  #tag(p.level) #h(2mm)#p.title])#label("problem-"+p.id)
 #if "capacity_note" in p {paragraph(p.capacity_note)}
 #grid(columns:(58pt,1fr),column-gutter:5pt,row-gutter:4pt,align:top,
  ..p.fields.map(field => (text(size:11pt,weight:"bold")[#field.label：],text(size:11pt)[#field.text])).flatten())
 #v(3mm)
 #for group in p.render_groups {
  if group.title!="" {paragraph(text(weight:"bold")[#group.title])}
  for (i,step) in group.steps.enumerate() {paragraph(str(i+1)+". "+step)}
 }
 #if p.visual.meta.len()>0 {
  block[#text(size:10pt,fill:muted)[#p.visual.meta.map(f=>f.label+"："+f.value).join(" · ")]]
 }
]
#let problem-view(p) = [
 // The explanation stays together; its table can use the remaining page.
 #block(breakable:false,above:3mm,below:2mm)[#problem-head(p)]
 #if p.representative_table != none {table-view(p.representative_table,flow:true)}
 #paragraph(p.references.pdf)
 #for note in p.object_notes {if note.starts-with("NSX Manager 的资源预留") {paragraph(note)}}
]
#let cluster-card(c)=block(breakable:false,width:100%,fill:surface,stroke:0.5pt+border,inset:9pt,radius:3pt)[
 #text(size:12pt,weight:"bold",fill:navy)[#c.name]#linebreak()
 #text(size:10.5pt,fill:muted)[#c.summary]#v(1mm)
 #for f in c.features {paragraph(f.label+" "+f.value)}
 #layout(size=>grid(columns:if size.width < 90mm {(1fr,)} else {(1fr,1fr)},column-gutter:3mm,row-gutter:2mm,
  ..c.fields.map(f=>text(size:10.5pt)[#f.label：#f.value])))
 #v(2mm)
 #for g in c.graphs [
  #text(size:10.5pt,weight:"semibold")[#g.title · #g.text]
  #block(width:100%,height:3mm,fill:white)[#rect(width:calc.min(100,g.value)*1%,height:3mm,fill:rgb("#8CA9BF"))]#v(1mm)
 ]
 #if c.host_names!="" [#text(size:10pt,fill:muted)[主机：#c.host_names]#linebreak()]
 #if c.cpu_models!="" [#text(size:10pt,fill:muted)[CPU 型号：#c.cpu_models]]
]
#let top-card(n)=block(breakable:false,width:100%,fill:surface,stroke:0.5pt+border,inset:8pt,radius:3pt)[
 #text(size:12pt,weight:"bold",fill:navy)[#n.title]#linebreak()
 #for note in n.notes [#text(size:10pt,fill:muted)[#note]#linebreak()]
 #v(2mm)
 #for r in visual.top.at(n.id) [
  #context {
   let name=text(size:10.5pt,weight:"bold")[#(str(r.rank)+".") #r.name]
   let meta=text(size:10pt,fill:muted)[#r.meta_text]
   if measure(name).width > 110mm { [#block[#name]#block[#meta]] }
   else {grid(columns:(auto,1fr,auto),column-gutter:2mm,align:top,
      text(size:10.5pt,weight:"bold")[#(str(r.rank)+".")],text(size:10.5pt,weight:"bold")[#r.name],meta)}
  }
  #v(1.5mm)
  #grid(columns:(1fr,auto),gutter:3mm,align:horizon,
   block(width:100%,height:3mm,fill:white)[#rect(width:r.bar_pct*1%,height:3mm,fill:rgb("#506B84"))],
   text(size:10.5pt,weight:"semibold")[#r.display])#v(2mm)
 ]
]
#let overview-table(section)=table(columns:(0.45fr,3fr,0.65fr),inset:5pt,stroke:0.45pt+border,
 table.header(..("等级","问题类别","受影响对象").map(h=>table.cell(fill:navy)[#text(size:10.5pt,fill:white,weight:"bold")[#h]])),
 ..section.rows.map(r=>(text(fill:grade-color(r.level),weight:"bold")[#r.level],text(size:10.5pt)[#r.title],text(size:10.5pt)[#r.objects])).flatten())

// Cover has only approved decision facts, not asset-scale KPIs.
#grid(columns:(1.1fr,0.9fr),gutter:7mm,align:top,
 block(width:100%,height:94mm,fill:navy,inset:10mm,radius:4pt)[
  #text(size:11pt,fill:rgb("#BBD4E9"),weight:"semibold")[客户交付报告]#v(5mm)
  #if visual.cover_label!="" [#text(size:11pt,fill:white)[#visual.cover_label]#linebreak()]
  #text(size:28pt,fill:white,weight:"bold")[#visual.display_title]#v(4mm)
  #line(length:100%,stroke:1pt+rgb("#7096B9"))#v(4mm)
  #for f in ((label:"客户名称",value:data.customer),(label:"巡检日期",value:data.date),(label:"平台版本",value:visual.platform)) {
   if f.value!="" [#grid(columns:(23mm,1fr),gutter:2mm,text(fill:rgb("#BBD4E9"))[#f.label],text(fill:white,weight:"semibold")[#f.value])#v(2mm)]
  }
  #if data.opening.statistics!="" [#v(2mm)#block(fill:rgb("#234C72"),inset:8pt,radius:3pt)[
   #text(size:10.5pt,fill:white,weight:"bold")[执行摘要]#linebreak()
   #text(size:10.5pt,fill:white)[#data.opening.statistics]]]
 ],stack(dir:ttb,spacing:5mm,..visual.opening_kpis.map(metric)))
#v(4mm)
#block(width:100%,fill:pale-blue,inset:9pt,radius:3pt)[
 #text(size:12pt,weight:"bold",fill:navy)[总体结论：#data.opening.conclusion]#linebreak()
 #if data.opening.priorities.len()>0 {
  text(size:11pt,weight:"bold")[需优先处理的问题]
  for item in data.opening.priorities [#block(above:1mm,below:1mm)[#tag(item.level) #h(2mm)#item.title #h(2mm)#item.objects 个受影响对象]]
 }
 #paragraph(data.opening.more)#paragraph(data.opening.statistics)
]
#pagebreak()
#heading(level:1,outlined:false)[目录]
#context [
 #show outline.entry: entry => {
  let target=entry.element
  let title=entry.body()
  if target.has("label") {
   for (index,section) in data.sections.enumerate() {
    if target.label == label(section.id) {
     let number=if index + 1 < 10 {"0"+str(index + 1)} else {str(index + 1)}
     title=[#number #section.title]
    }
    if section.kind=="problems" {
     for p in section.items {
      if target.label == label("problem-"+p.id) {title=[#p.level #p.title]}
     }
    }
   }
  }
  link(target.location(),entry.indented(none,[
   #text(size:if entry.level==1 {15pt} else {11pt},fill:ink)[#title]
   #box(width:1fr,entry.fill) #entry.page()
  ]))
 }
 #outline(title:none,depth:2,indent:1.5em)
]
#v(3mm)
#for (index,section) in data.sections.enumerate() {
 let number=if index + 1 < 10 {"0"+str(index+1)} else {str(index+1)}
 [#page-title(number,section.title,
  subtitle:visual.section_subtitles.at(section.kind))#label(section.id)]
 if section.kind=="overview" {
  if visual.has_execution_stats {
  block(breakable:false)[
   #metrics(((label:"检查总数",value:str(data.statistics.total),detail:""),(label:"通过",value:str(data.statistics.passed),detail:""),(label:"未通过",value:str(data.statistics.failed),detail:"")))#v(2mm)
   #text(size:10.5pt,fill:muted)[通过比例 #visual.scope.pass_percent_text]
   #block(width:100%,height:4mm,fill:surface)[#rect(width:visual.scope.pass_percent*1%,height:4mm,fill:rgb("#506B84"))]#v(3mm)
   #grid(columns:(1.3fr,1fr),gutter:5mm,align:top,
    overview-table(section),
    block(fill:pale-blue,inset:9pt,radius:3pt)[
     #text(size:11pt,weight:"bold",fill:navy)[未通过检查结果按等级分布]#v(2mm)
     #grid(columns:(44mm,1fr),gutter:3mm,align:horizon,
      image("scope-level-donut.svg",width:44mm,height:44mm),
      stack(dir:ttb,spacing:3mm,..visual.scope.level_distribution.map(r=>[
       #tag(r.level) #linebreak()#text(size:10.5pt)[#r.count 条 · #r.share_pct_text]])))])
  ]
  } else {overview-table(section)}
 } else if section.kind=="problems" {
  for p in section.items {problem-view(p)}
 } else if section.kind=="checklist" {
  for rows in section.items.chunks(2) [#grid(columns:(1fr,1fr),gutter:6mm,
   ..rows.map(item=>block(breakable:false,below:2mm)[✓ #item.label]))]
 } else if section.kind=="environment" {
  for group in section.groups {
   if group.id=="resource-top" {block(sticky:true,above:2mm,below:1mm)[#heading(level:2,group.title)]}
   else {heading(level:2)[#group.title]}
   if group.id=="scale-clusters" {
    metrics(visual.asset_kpis);v(3mm)
    if "vm_state_card" in visual {
     let c=visual.vm_state_card
     block(breakable:false,width:100%,fill:surface,inset:8pt,radius:3pt)[
      #text(weight:"bold",fill:navy)[#c.title]#linebreak()
      #c.segments.map(s=>[#s.label #s.value]).join([ · ])
      #if c.total>0 {v(2mm);grid(columns:c.segments.filter(s=>s.value>0).map(s=>s.value*1fr),
       ..c.segments.filter(s=>s.value>0).map(s=>rect(width:100%,height:3mm,fill:rgb(s.color))))}
     ];v(2mm)
    }
    if visual.snapshots.len()>0 {metrics(visual.snapshots);v(2mm)}
    if "clusters" in visual.narratives {story(visual.narratives.clusters);v(2mm)}
    for node in group.blocks {
     if node.id=="cluster-summary" {
      if node.kind=="cards" {grid(columns:range(node.rows.len()).map(_=>1fr),gutter:4mm,
        ..node.rows.map(r=>cluster-card(visual.clusters.at(r.key))))}
      else {table-view(node)}
     } else if node.id not in ("scale","snapshot-overview") {
      if node.kind=="paragraph" {paragraph(node.text)} else if node.kind=="table" {table-view(node)}
     }
    }
    if visual.cluster_coverage.len()>0 {v(2mm);grid(columns:range(visual.cluster_coverage.len()).map(_=>1fr),gutter:3mm,
     ..visual.cluster_coverage.map(c=>block(breakable:false,width:100%,fill:surface,inset:8pt,radius:3pt)[
      #text(weight:"bold",fill:navy)[#c.title] #c.value/#c.total
      #v(2mm)#block(width:100%,height:3mm,fill:white)[#rect(width:c.value/c.total*100%,height:3mm,fill:rgb("#8CA9BF"))]
      #if c.text!="" [#linebreak()#text(size:10.5pt,fill:muted)[#c.text]]]))}
   } else if group.id=="host-resources" {
    metrics(visual.host_kpis);v(2mm)
    if "hosts" in visual.narratives {story(visual.narratives.hosts);v(2mm)}
    let allocations=("allocation_cpu","allocation_memory").filter(k=>k in visual).map(k=>visual.at(k))
    if allocations.len()>0 {grid(columns:range(allocations.len()).map(_=>1fr),gutter:4mm,..allocations.map(graph));v(2mm)}
    let charts=group.blocks.filter(n=>n.kind=="chart" and n.id!="memory_allocation_pct")
    if charts.len()>0 {grid(columns:range(calc.min(2,charts.len())).map(_=>1fr),gutter:4mm,..charts.map(graph))}
    for node in group.blocks {if node.kind=="table" {table-view(node)} else if node.kind=="paragraph" {story(node.text)}}
   } else if group.id=="resource-top" {
    grid(columns:(1fr,1fr),column-gutter:4mm,row-gutter:2mm,..group.blocks.map(top-card))
   } else if group.id=="storage" {
    if visual.vsan_cards.len()>0 {metrics(visual.vsan_cards);v(3mm)}
    for node in group.blocks {
     if node.id=="storage-ranking" {
      [#block(sticky:true)[#text(size:12pt,weight:"bold",fill:navy)[#node.title]]#v(2mm)
       #grid(columns:(1fr,1fr),column-gutter:5mm,row-gutter:2mm,..node.rows.map(row=>{
        let ds=visual.storage.at(row.key)
        block(breakable:false)[
         #grid(columns:(1fr,auto),gutter:3mm,text(size:10.5pt,weight:"semibold")[#row.name],text(size:10.5pt)[#ds.usage_text #if ds.clusters.len()>0 [ · #ds.clusters.join("、")]])
         #if ds.capacity_text!="" [#text(size:10pt,fill:muted)[#ds.capacity_text]]
         #block(width:100%,height:3mm,fill:surface)[#rect(width:ds.usage*1%,height:3mm,fill:rgb("#8CA9BF"))]
        ]
       }))
       #for note in node.notes {paragraph(note)}]
     } else if node.id=="vsan" {
      for rows in node.rows.chunks(4) {metrics(rows.map(r=>(label:r.cells.first(),value:r.cells.last(),detail:"")));v(2mm)}
     } else if node.kind=="paragraph" {story(node.text)} else if node.kind=="table" {table-view(node)}
    }
   } else if group.id in ("network","security-certificates") {
    let summary=visual.group_summaries.at(group.id)
    if summary.text!="" {story(summary.references.pdf.text);v(2mm)}
    for node in group.blocks {if node.kind=="table" {table-view(node)}}
   } else {
    for node in group.blocks {if node.kind=="table" {table-view(node)} else if node.kind=="paragraph" {story(node.text)} else if node.kind=="chart" {graph(node)}}
   }
   v(3mm)
  }
 }
}
