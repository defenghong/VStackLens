"""Accessible offline HTML for the shared body and full appendix registry."""
from __future__ import annotations

from html import escape
import json

from vstacklens.reports.document_model import get_document, COLORS, NAVY, INK
from vstacklens.reports.document_output import document_for_medium

CSS = r'''
:root{--navy:#163B63;--ink:#24364A;--muted:#64748B;--line:#B9C8D6;--surface:#F1F5F9;--p1:#B3261E;--p2:#A15C07;--p3:#3F6688}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#F4F6F9;color:var(--ink);font:16px/1.65 "Microsoft YaHei","Segoe UI",sans-serif}
.shell{max-width:1220px;margin:auto;background:white;min-height:100vh;padding:26px 34px 48px}header{display:flex;gap:24px;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:16px}
h1{font-size:30px;line-height:1.35;color:var(--navy);margin:0}h2{font-size:24px;line-height:1.4;color:var(--navy);margin:24px 0 12px}h3{font-size:19px;line-height:1.5;color:var(--navy);margin:18px 0 8px}p{margin:8px 0}
nav{display:flex;flex-wrap:wrap;gap:10px 24px;padding:15px 0;border-bottom:1px solid var(--line)}a{color:var(--navy);text-underline-offset:3px}a:hover{text-decoration-thickness:2px}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--navy);outline-offset:3px}
button,input,select{font:inherit;border:1px solid var(--line);border-radius:5px;background:white;color:var(--ink);padding:7px 10px;min-height:40px}button{cursor:pointer}summary{cursor:pointer;color:var(--navy);font-weight:600;padding:10px 0;overflow-wrap:anywhere}details{scroll-margin-top:18px}details.section{border-bottom:1px solid var(--line);padding:10px 0 20px}details.section>summary{font-size:24px}details.problem>summary{font-size:19px}
.opening{min-height:calc(100svh - 185px);padding:28px 0 34px}.conclusion{font-size:25px;font-weight:700}.problem-count{font-size:21px;font-weight:600}.priorities{padding-left:0;list-style:none;max-width:85ch}.priorities li{display:flex;align-items:baseline;gap:12px;margin:12px 0}.badge{display:inline-block;font-weight:700;border:1px solid currentColor;border-radius:4px;padding:0 7px;white-space:nowrap}.P1{color:var(--p1)}.P2{color:var(--p2)}.P3{color:var(--p3)}.count,.value{color:var(--ink);font-weight:500}.meta,.hint,.reference{color:var(--muted);font-size:14px}.table-scroll{overflow-x:auto;max-width:100%;border:1px solid var(--line);margin:10px 0 14px;overscroll-behavior-x:contain}.scroll-hint{display:none;margin:5px 0}.table-scroll.can-scroll+.scroll-hint{display:block}
table{border-collapse:collapse;width:100%;font:inherit;table-layout:fixed}th,td{border-bottom:1px solid #D7E0E9;padding:9px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:normal}th{background:var(--navy);color:white;font-size:15px;font-weight:600}td{font-size:15px;white-space:pre-wrap}tr:last-child td{border-bottom:0}.filters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;background:var(--surface);padding:14px;margin:14px 0}.filters label{display:grid;gap:4px;min-width:140px}.filters label:first-child{flex:1;min-width:220px}.filters input,.filters select{width:100%}.appendix[hidden],tr[hidden]{display:none}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.cluster-card{background:var(--surface);padding:16px;border-radius:6px}.cluster-card dt{font-weight:500;color:var(--muted)}.cluster-card dd{margin:0 0 5px;overflow-wrap:anywhere}.chart{margin:18px 0;break-inside:avoid}.chart-row{display:grid;grid-template-columns:220px minmax(120px,1fr) 88px;gap:12px;align-items:center;margin:8px 0}.chart-label{font-size:15px;overflow-wrap:anywhere}.track{position:relative;height:14px;background:var(--surface)}.bar{display:block;height:100%;background:var(--muted)}.threshold{position:absolute;top:-4px;bottom:-4px;width:1px;background:var(--navy)}.ticks{display:flex;justify-content:space-between;margin-left:232px;margin-right:100px;font-size:13px;color:var(--muted)}.grade-bar{height:12px;background:var(--surface);flex:1}.grade-bar>span{display:block;height:100%}.distribution{display:grid;gap:10px;margin:16px 0}.distribution>div{display:flex;gap:14px;align-items:center}.distribution .badge{width:46px}.distribution .count{width:54px}
@media(max-width:650px){.shell{padding:18px 16px 32px}header{display:block}header button{margin-top:12px}h1{font-size:29px}h2,details.section>summary{font-size:23px}.opening{min-height:calc(100svh - 230px)}.cards{grid-template-columns:1fr}.table-scroll>table{min-width:0}.chart-row{grid-template-columns:110px minmax(90px,1fr) 72px;gap:8px}.ticks{margin-left:118px;margin-right:80px}.filters{display:grid;grid-template-columns:1fr}.filters label,.filters label:first-child{min-width:0}.priorities li{align-items:flex-start}}
@media print{body{background:white;font-size:11pt}.shell{max-width:none;padding:0}nav,header button,.filters,.scroll-hint{display:none!important}.opening{min-height:0;break-after:page}details>summary{list-style:none}details.section{border:0}details{display:block}details> :not(summary){display:block}table{width:100%;min-width:0!important}th,td{font-size:10.5pt}thead{display:table-header-group}tr{break-inside:avoid}.table-scroll{overflow:visible;border:0}.cards,.chart{break-inside:avoid}h2,h3,summary{break-after:avoid}.reference{font-size:10.5pt}}
'''

JS = r'''
"use strict";
const D=JSON.parse(document.getElementById("document-data").textContent);
const E=s=>String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\u0022/g,"&quot;").replace(/'/g,"&#39;");
const badge=l=>`<span class="badge ${E(l)}">${E(l)}</span>`;
function table(t){if(!t?.rows?.length)return "";
 const widths=t.weights.map((w,i)=>Math.max(90,w*80,Math.min(280,t.headers[i].length*15+20))),total=widths.reduce((a,b)=>a+b,0);
 const cols=widths.map(w=>`<col style="width:${100*w/total}%">`).join("");
 return `<div class="table-scroll" tabindex="0" role="region" aria-label="${E(t.title)}"><table style="min-width:${total}px" data-table="${E(t.id)}"><colgroup>${cols}</colgroup><thead><tr>${t.headers.map(h=>`<th>${E(h)}</th>`).join("")}</tr></thead><tbody>${t.rows.map(r=>`<tr data-row="${E(r.id)}">${r.cells.map((v,i)=>`<td>${t.headers[i]==="等级"&&D.colors[v]?badge(v):E(v)}</td>`).join("")}</tr>`).join("")}</tbody></table></div><p class="hint scroll-hint">表格可左右滑动查看</p>${(t.notes||[]).map(n=>`<p>${E(n)}</p>`).join("")}`;
}
function graph(g){return `<div class="chart"><h3>${E(g.title)}</h3>${g.series.map(r=>`<div class="chart-row"><span class="chart-label">${E(r.name)}</span><div class="track"><span class="bar" style="width:${100*r.value/g.axis_max}%"></span><span class="threshold" style="left:${100*g.threshold/g.axis_max}%"></span></div><span class="value">${E(r.text)}</span></div>`).join("")}<div class="ticks">${g.ticks.map(t=>`<span>${E(t.text)}</span>`).join("")}</div>${g.more?`<p class="reference">${E(g.more)}</p>`:""}</div>`}
function problem(p){const highest=D.sections.find(s=>s.kind==="problems")?.items[0]?.level;
 const fields=p.fields.map(f=>[f.label,f.text]);
 const groups=p.render_groups;
 return `<details class="problem" id="problem-${E(p.id)}" ${p.level===highest?"open":""}><summary>${badge(p.level)} ${E(p.title)}</summary>${p.capacity_note?`<p>${E(p.capacity_note)}</p>`:""}${fields.map(([l,t])=>`<p><strong>${E(l)}：</strong>${E(t)}</p>`).join("")}${groups.map(g=>`${g.title?`<h3>${E(g.title)}</h3>`:""}<ol>${g.steps.map(step=>`<li>${E(step)}</li>`).join("")}</ol>`).join("")}${table(p.representative_table)}${p.reference?`<p class="reference">${E(p.reference)}</p>`:""}${p.objects>5?`<p><a class="view-all" href="#appendix-${E(p.appendix)}">查看全部 ${E(p.objects)} 个</a></p>`:""}${p.object_notes.filter(n=>n.startsWith("NSX Manager 的资源预留")).map(n=>`<p>${E(n)}</p>`).join("")}</details>`
}
function block(n){if(n.presentation==="ranked-cards")return `<h3>${E(n.title)}</h3>${n.rows.map(r=>`<article class="rank-item" style="border-bottom:1px solid var(--line);padding:10px 0;overflow-wrap:anywhere"><strong>${E(r.name)}</strong><p>${E(r.detail)}</p></article>`).join("")}${n.notes.map(v=>`<p>${E(v)}</p>`).join("")}`;
 if(n.kind==="table")return `<h3>${E(n.title)}</h3>${table(n)}${n.reference?`<p class="reference">${E(n.reference)}</p>`:""}`;
 if(n.kind==="paragraph")return `${n.title?`<h3>${E(n.title)}</h3>`:""}<p>${E(n.text)}</p>`;
 if(n.kind==="chart")return graph(n);
 if(n.kind==="cards")return `<h4>${E(n.title)}</h4><div class="cards">${n.rows.map(r=>`<article class="cluster-card"><h4>${E(r.cells[0])}</h4><dl>${r.cells.slice(1).map((v,i)=>`<dt>${E(n.headers[i+1])}</dt><dd>${E(v)}</dd>`).join("")}</dl></article>`).join("")}</div>`;
 return "";
}
document.getElementById("opening").innerHTML=`<p class="conclusion">总体结论：${E(D.opening.conclusion)}</p><p class="problem-count">${E(D.opening.problem_text)}</p>${D.opening.priorities.length?`<h2>需优先处理的问题</h2><ul class="priorities">${D.opening.priorities.map(p=>`<li>${badge(p.level)}<span>${E(p.title)} <span class="count">${E(p.objects)} 个受影响对象</span></span></li>`).join("")}</ul>`:""}${D.opening.more?`<p><a href="#overview">${E(D.opening.more)}</a></p>`:""}${D.opening.statistics?`<p>${E(D.opening.statistics)}</p>`:""}`;
document.getElementById("body-sections").innerHTML=D.sections.map(s=>{
 let body="";
 if(s.kind==="overview"){const t={id:"overview",title:s.title,weights:[1,5,1],headers:["等级","问题类别","受影响对象"],rows:s.rows.map((r,i)=>({id:"overview"+i,cells:[r.level,r.title,r.objects]}))};body=table(t)+`<h3>问题等级分布</h3><div class="distribution">${Object.keys(D.colors).map(l=>`<div>${badge(l)}<div class="grade-bar"><span style="width:${100*s.levels[l]/Math.max(D.counts.categories,1)}%;background:${E(D.colors[l])}"></span></div><span class="count">${E(s.levels[l])} 类</span></div>`).join("")}</div>`}
 else if(s.kind==="problems")body=s.items.map(problem).join("");
 else if(s.kind==="checklist")body=`<ul>${s.items.map(i=>`<li>✓ ${E(i.label)}</li>`).join("")}</ul>`;
 else if(s.kind==="environment")body=s.groups.map(g=>`<section><h3>${E(g.title)}</h3>${g.blocks.map(block).join("")}</section>`).join("");
 return `<details class="section" id="${E(s.id)}" ${s.kind==="overview"||s.kind==="problems"?"open":""}><summary><h2 style="display:inline">${E(s.title)}</h2></summary>${body}</details>`;
}).join("");
document.getElementById("appendix-tables").innerHTML=D.appendices.map(a=>`<details class="appendix" id="${E(a.anchor)}"><summary>附录 ${E(a.letter)} ${E(a.title)} <span class="meta">共 ${a.rows.length} 行</span></summary>${table(a)}</details>`).join("");
function options(id,values){const e=document.getElementById(id);[...new Set(values)].filter(Boolean).sort().forEach(v=>{const o=document.createElement("option");o.value=v;o.textContent=v;e.append(o)})}
options("filter-cluster",D.appendices.flatMap(a=>a.rows.map(r=>r.cluster)));options("filter-host",D.appendices.flatMap(a=>a.rows.map(r=>r.host)));options("filter-category",D.appendices.flatMap(a=>a.rows.map(r=>r.category)));
const byId=new Map(D.appendices.flatMap(a=>a.rows.map(r=>[r.id,r])));
function applyFilters(){const q=document.getElementById("filter-search").value.toLocaleLowerCase();const c=document.getElementById("filter-cluster").value,h=document.getElementById("filter-host").value,k=document.getElementById("filter-category").value;
 D.appendices.forEach(a=>{const e=document.getElementById(a.anchor);let count=0;e.querySelectorAll("tbody tr").forEach(tr=>{const r=byId.get(tr.dataset.row);const ok=(!q||r.cells.join(" ").toLocaleLowerCase().includes(q))&&(!c||r.cluster===c)&&(!h||r.host===h)&&(!k||r.category===k);tr.hidden=!ok;if(ok)count++});e.hidden=count===0;e.querySelector("summary .meta").textContent=`${count} / ${a.rows.length} 行`;if(q||c||h||k)e.open=count>0});scrollHints();}
document.querySelectorAll(".filters input,.filters select").forEach(e=>e.addEventListener(e.tagName==="INPUT"?"input":"change",applyFilters));
function scrollHints(){document.querySelectorAll(".table-scroll").forEach(e=>e.classList.toggle("can-scroll",e.scrollWidth>e.clientWidth+1))}
document.addEventListener("toggle",scrollHints,true);window.addEventListener("resize",scrollHints);
document.querySelectorAll('a[href^="#"]').forEach(a=>a.addEventListener("click",()=>{let e=document.querySelector(a.getAttribute("href"));for(let p=e;p;p=p.parentElement)if(p.tagName==="DETAILS")p.open=true;requestAnimationFrame(()=>{scrollHints();e?.scrollIntoView({block:"start"})})}));
const printing=new Map();window.addEventListener("beforeprint",()=>{document.querySelectorAll("details").forEach(e=>{printing.set(e,e.open);e.open=true})});window.addEventListener("afterprint",()=>{printing.forEach((v,e)=>e.open=v);printing.clear()});scrollHints();
window.VSTACKLENS_DOCUMENT_READY=true;
'''


from vstacklens.reports.document_html_visual import apply as _apply_visual
CSS,JS=_apply_visual(CSS,JS)


def html_page(document):
    title=escape(document['title'])
    customer='' if document['customer'] and document['title'].startswith(document['customer']) else document['customer']
    meta=' · '.join(value for value in (customer,document['date_label']) if value)
    meta_markup=f'<p class="meta">{escape(meta)}</p>' if meta else ''
    embedded=json.dumps(document,ensure_ascii=False,separators=(',',':')).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    nav=''.join(f'<a href="#{escape(n["id"])}">{escape(n["title"])}</a>' for n in document['navigation'])
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title><link rel="stylesheet" href="assets/report.css"></head><body><div class="shell"><header><div><h1><span class="brand-mark" aria-hidden="true">V</span><span class="report-name">{title}</span></h1>{meta_markup}</div><button onclick="window.print()">打印</button></header><nav aria-label="报告目录"><a href="#opening">结论</a>{nav}<a href="#appendices">附录</a></nav><main><section id="opening" class="opening"></section><div id="body-sections"></div><details class="section" id="appendices"><summary>附录</summary><div class="filters"><label>搜索完整清单<input id="filter-search" type="search" placeholder="输入对象名称或路径"></label><label>集群<select id="filter-cluster"><option value="">全部集群</option></select></label><label>主机<select id="filter-host"><option value="">全部主机</option></select></label><label>问题类别<select id="filter-category"><option value="">全部类别</option></select></label></div><div id="appendix-tables"></div></details></main></div><script id="document-data" type="application/json">{embedded}</script><script src="assets/report.js"></script></body></html>'''


def write_document_html(report,context,stage):
    document=document_for_medium(get_document(report,context),'html')
    (stage/'data/customer_report_payload.json').write_text(json.dumps({'title':document['title'],'document':document,**document['metadata']},ensure_ascii=False,indent=2),'utf-8')
    (stage/'assets/report.css').write_text(CSS,'utf-8')
    (stage/'assets/report.js').write_text(JS,'utf-8')
    (stage/'index.html').write_text(html_page(document),'utf-8')
    return document
