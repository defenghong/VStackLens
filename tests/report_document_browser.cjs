/* Real offline browser checks; no network requests and no product mutations. */
const fs=require('fs'),path=require('path');
const {pathToFileURL}=require('url');
const {chromium}=require('playwright');
const sharp=require('sharp');
(async()=>{
 const root=path.resolve(process.argv[2]),documentData=JSON.parse(fs.readFileSync(path.join(root,'document.json'),'utf8'));
 const browser=await chromium.launch({channel:'msedge',headless:true});const results=[];
 try{for(const width of [1440,390]){
  const context=await browser.newContext({viewport:{width,height:1000},deviceScaleFactor:1});const page=await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.route(/^https?:/,route=>route.abort());
  const samples=[];
  for(let sample=0;sample<3;sample++){
   const start=performance.now();await page.goto(pathToFileURL(path.join(root,'html','index.html')).href);
   await page.waitForFunction(()=>window.VSTACKLENS_DOCUMENT_READY);samples.push(performance.now()-start);
  }
  const initially=await page.locator('details.problem[open]').count();
  await page.evaluate(()=>document.fonts.ready);
  const firstBuffer=await page.screenshot({clip:{x:0,y:0,width,height:900}});
  const decoded=await sharp(firstBuffer).removeAlpha().raw().toBuffer({resolveWithObject:true});
  let whitespace=0;
  for(let i=0;i<decoded.data.length;i+=decoded.info.channels){if(decoded.data[i]>=240&&decoded.data[i+1]>=240&&decoded.data[i+2]>=240)whitespace++;}
  const firstScreen={white_ratio:whitespace/(decoded.info.width*decoded.info.height),width,height:900,
    definition:'Actual PNG, RGB channels >=240; no threshold based on sample name'};
  const highest=documentData.sections.find(s=>s.kind==='problems')?.items[0]?.level;
  const expectedOpen=documentData.sections.find(s=>s.kind==='problems')?.items.filter(i=>i.level===highest).length||0;
  if(initially!==expectedOpen)throw Error('Unexpected default expanded problems');
  await page.evaluate(()=>document.querySelectorAll('details').forEach(d=>d.open=true));
  const qa=await page.evaluate(()=>{
   const D=JSON.parse(document.getElementById('document-data').textContent),failures=[];
   const rows=D.appendices.flatMap(a=>a.rows);
   for(const field of ['cluster','host','category']){
    const counts=new Map();rows.forEach(r=>counts.set(r[field],(counts.get(r[field])||0)+1));
    if([...counts.values()].reduce((a,b)=>a+b,0)!==rows.length)failures.push(field+' counts');
    const options=[...document.getElementById('filter-'+field).options].slice(1).map(o=>o.value);
    if(options.length!==counts.size)failures.push(field+' options');
   }
   const uniqueNames=[...new Set(rows.map(r=>r.name))];
   for(const name of uniqueNames){if(!rows.some(r=>r.cells.join(' ').toLocaleLowerCase().includes(name.toLocaleLowerCase())))failures.push('unsearchable '+name)}
   for(const a of D.appendices){const t=document.getElementById(a.anchor),actual=[...t.querySelectorAll('tbody tr')];
    if(actual.length!==a.rows.length)failures.push(a.letter+' rows');
    actual.forEach((tr,i)=>{if([...tr.cells].some((c,j)=>c.textContent!==a.rows[i].cells[j]))failures.push(a.letter+' cell '+i)})}
   const outside=[...document.querySelectorAll('h1,h2,h3,p,summary,input,select,.shell')].filter(e=>{const b=e.getBoundingClientRect();return b.width&& (b.left<-.8||b.right>innerWidth+.8)}).map(e=>e.tagName+':'+e.textContent.slice(0,60));
   const narrowColumns=[...document.querySelectorAll('th')].filter(e=>{const width=e.getBoundingClientRect().width;return width>0&&width<80}).map(e=>e.textContent);
   return {failures,rows:rows.length,uniqueNames:uniqueNames.length,appendices:D.appendices.map(a=>({letter:a.letter,title:a.title,rows:a.rows.length})),
    outside,narrowColumns,text:document.body.innerText,h1:parseFloat(getComputedStyle(document.querySelector('h1')).fontSize),h2:parseFloat(getComputedStyle(document.querySelector('h2')||document.querySelector('summary')).fontSize),
    pageWidth:document.documentElement.scrollWidth,viewport:innerWidth,scrolling:document.querySelectorAll('.table-scroll.can-scroll').length};
  });
  if(qa.failures.length||qa.outside.length||qa.narrowColumns.length||qa.pageWidth>width+1||qa.h1<=qa.h2)throw Error(JSON.stringify(qa));
  // Exercise actual DOM filters, in addition to the exhaustive source index.
  const filterResults=[];
  for(const field of ['cluster','host','category']){
   const options=await page.locator('#filter-'+field+' option').evaluateAll(os=>os.slice(1).map(o=>o.value));
   for(const value of options){
    await page.selectOption('#filter-'+field,value);
    const count=await page.locator('#appendix-tables tbody tr:not([hidden])').count();
    const expected=documentData.appendices.flatMap(a=>a.rows).filter(r=>r[field]===value).length;
    if(count!==expected)throw Error(field+' '+value+' '+count+' != '+expected);
    filterResults.push({field,value,count});
   }
   await page.selectOption('#filter-'+field,'');
  }
  const unique=[...new Set(documentData.appendices.flatMap(a=>a.rows.map(r=>r.name)))];
  const searchResults=[];
  for(const name of [...new Set([unique[0],unique.at(-1),unique.reduce((a,b)=>a.length>b.length?a:b,'')])].filter(Boolean)){
   await page.fill('#filter-search',name);
   const count=await page.locator('#appendix-tables tbody tr:not([hidden])').count();
   if(count<1)throw Error('DOM search failed '+name);
   searchResults.push({name,count});
  }
  await page.fill('#filter-search','');
  if(errors.length)throw Error(errors.join('\n'));
  const cardGeometry=await page.evaluate(()=>[...document.querySelectorAll('.cluster-grid,.top-grid,.host-grid')].flatMap(container=>{
    const cards=[...container.children].filter(e=>e.getBoundingClientRect().width>0),groups=[];
    for(const e of cards){const r=e.getBoundingClientRect();let row=groups.find(g=>Math.abs(g[0].top-r.top)<2);if(!row){row=[];groups.push(row)}row.push(r)}
    return groups.filter(g=>g.length>1).map(g=>({cards:g.length,occupied:g.reduce((a,r)=>a+r.width,0)/container.getBoundingClientRect().width,
      equal:Math.max(...g.map(r=>r.width))-Math.min(...g.map(r=>r.width))<2}));
  }));
  const viewAllLinks=[];
  const linkCount=await page.locator('.view-all').count();
  for(let index=0;index<linkCount;index++){
   const link=page.locator('.view-all').nth(index),href=await link.getAttribute('href');
   await link.evaluate(e=>{for(let p=e.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;
    const target=document.querySelector(e.getAttribute('href'));if(target)target.open=false;const outer=document.getElementById('appendices');outer.open=false;});
   await link.click();
   const state=await page.locator(href).evaluate(e=>{let opened=true;for(let p=e;p;p=p.parentElement)if(p.tagName==='DETAILS'&&!p.open)opened=false;
    return {exists:true,opened,visible:e.getBoundingClientRect().height>0,rows:e.querySelectorAll('tbody tr:not([hidden])').length};});
   if(!state.opened||!state.visible||state.rows===0)throw Error('View-all click did not reveal complete list '+href);
   viewAllLinks.push({href,...state,clicked:true});
  }
  const axisGeometry=await page.evaluate(()=>[...document.querySelectorAll('.axis-labels')].filter(e=>e.getBoundingClientRect().width>0).map(e=>{
   const card=e.closest('.chart').getBoundingClientRect();
   return {title:e.closest('.chart').querySelector('h4').textContent,card_left:card.left,card_right:card.right,
    ticks:[...e.querySelectorAll(':scope>span')].map(t=>{const b=t.getBoundingClientRect();return {text:t.textContent,left:b.left,right:b.right,top:b.top,value:Number(t.dataset.fraction)}})};
  }));
  const openingDisplay=await page.evaluate(()=>({problem_count_lines:document.querySelectorAll('#opening .problem-count').length,
   executive:document.querySelector('#opening .executive p')?.textContent||'',
   kpis:[...document.querySelectorAll('#opening .cover-kpis .metric')].map(m=>({label:m.querySelector('.metric-label').textContent,value:m.querySelector('.metric-value').textContent,detail:m.querySelector('.metric-detail')?.textContent||''}))}));
  results.push({width,samples_ms:samples.map(v=>Math.round(v*100)/100),default_open:initially,qa,filterResults,searchResults,errors,firstScreen,cardGeometry,viewAllLinks,axisGeometry,openingDisplay});
  await context.close();
 }}finally{await browser.close()}
 fs.writeFileSync(path.join(root,'browser.json'),JSON.stringify(results,null,2));
 console.log(JSON.stringify(results.map(r=>({width:r.width,rows:r.qa.rows,searchable:r.qa.uniqueNames,ms:r.samples_ms,scrolling:r.qa.scrolling}))));
})().catch(e=>{console.error(e.stack);process.exitCode=1});
