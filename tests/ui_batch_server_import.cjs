// Real Chromium with mocked API: multi-server grouping and composite node IDs.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(resolve=>host.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:'+host.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.profile='clash';S.page='nodes';S.profiles=[{id:'clash',name:'订阅一'}];
   S.data={nodes:[],groups:[],rules:[],profile:{name:'订阅一',traffic:{configured:false,bindings:[]}}};
   Object.assign(window,{calls:[],inboundCalls:[],failOnce:true,created:new Set(),serverCount:2,activeLoads:0,maxActiveLoads:0,failLoad:'',manyNodes:false});
   api=async(url,opt)=>{
    if(url==='/snapshot')return S.data;
    if(url==='/servers')return {servers:Array.from({length:window.serverCount},(_,n)=>({id:'server-'+(n+1),name:n?'美国服务器 '+(n+1):'日本服务器',host:'198.51.100.'+(n+1),installType:'x-panel'}))};
    if(url.startsWith('/servers/inbounds?')){
     const id=new URLSearchParams(url.split('?')[1]).get('id');window.inboundCalls.push(id);
     window.activeLoads++;window.maxActiveLoads=Math.max(window.maxActiveLoads,window.activeLoads);
     try{
      await new Promise(resolve=>setTimeout(resolve,100));
      if(window.failLoad===id)throw Error('此服务器暂时离线，请重试');
      const ids=window.manyNodes?Array.from({length:60},(_,i)=>i+1):id==='server-1'?[1,2,3,4,5,6]:id==='server-2'?[1,2]:[1];
      return {inbounds:ids.map(inboundId=>({id:inboundId,port:24000+inboundId,remark:window.manyNodes?'x'.repeat(90):id+' 节点-'+inboundId,protocol:!window.manyNodes&&inboundId===5?'shadowsocks':'vless',enable:window.manyNodes||inboundId!==6}))};
     }finally{window.activeLoads--;}
    }
    if(url==='/servers/users/batch'){
     const body=JSON.parse(opt.body);window.calls.push({body,profile:opt.headers['X-Profile']});
     if([...document.querySelectorAll('.batchServerSource,.batchServerChoice')].some(n=>!n.disabled))throw Error('selection changed during import');
     const results=body.inboundIds.map(inboundId=>{
      if(window.failOnce && body.serverId==='server-2' && inboundId===1)return {inboundId,ok:false,error:'连接超时，绑定待核对'};
      const key=body.serverId+'/'+inboundId,existing=window.created.has(key)?1:0;window.created.add(key);return {inboundId,ok:true,added:1-existing,existing};
     });
     return {results,traffic:{configured:true,enforce:true,bindings:[],total:1024**3,expire:2000000000,upload:123,download:456}};
    }
    throw Error('unexpected '+url);
   };
  });
  const click=async selector=>{await page.$eval(selector,n=>n.scrollIntoView({block:'center',behavior:'instant'}));await page.click(selector);};
  const waitNodes=count=>page.waitForFunction(n=>document.querySelectorAll('.batchServerChoice').length===n,{},count);
  for(const theme of ['high','low','pink'])for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(async theme=>{S.profile='clash';S.page='nodes';window.failOnce=true;window.calls=[];window.inboundCalls=[];setTheme(theme);await batchServerImport();},theme);
   assert.equal((await page.evaluate(()=>window.inboundCalls.length)),0,'no server contacts before selection');
   await click('.batchServerSource[value="server-1"]');await click('.batchServerSource[value="server-2"]');await waitNodes(8);
   assert.equal(await page.$$eval('[data-batch-server-group]',nodes=>nodes.length),2);
   assert.equal(await page.$$eval('.batchServerChoice:disabled',nodes=>nodes.length),2);
   await click('#batchServerAll');assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),6);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,theme+'-multi-server-'+width+'.png'),fullPage:true});}
   await page.$eval('#batchServerSubmit',n=>n.scrollIntoView({block:'center'}));await click('#batchServerSubmit');
   await page.waitForFunction(()=>$('batchServerProgress')?.textContent.includes('已处理 6 / 6'));
   assert((await page.$eval('#batchServerProgress',n=>n.textContent)).includes('成功 5，失败 1'));
   assert.deepEqual(await page.evaluate(()=>window.calls.map(x=>x.body)),[
    {serverId:'server-1',inboundIds:[1,2,3]},{serverId:'server-1',inboundIds:[4]},{serverId:'server-2',inboundIds:[1,2]}
   ]);
   assert((await page.evaluate(()=>window.calls)).every(x=>x.profile==='clash'));
   assert.deepEqual(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.map(n=>JSON.parse(n.value))),[['server-2',1]],'same inbound ID on another server must remain selected on failure');
   await page.evaluate(()=>{window.failOnce=false;});await click('#batchServerSubmit');
   await page.waitForFunction(()=>$('batchServerProgress')?.textContent.includes('成功 1，失败 0'));
   assert.deepEqual(await page.evaluate(()=>window.calls.at(-1).body),{serverId:'server-2',inboundIds:[1]});
   assert.equal(await page.evaluate(()=>S.data.profile.traffic.upload),123);
   const loads=await page.evaluate(()=>window.inboundCalls.length);
   await click('.batchServerSource[value="server-2"]');assert.equal(await page.$$eval('[data-batch-server-group]',nodes=>nodes.length),1);
   await click('.batchServerSource[value="server-2"]');await waitNodes(8);assert.equal(await page.evaluate(()=>window.inboundCalls.length),loads,'reselect reuses this dialog snapshot');
   await click('#batchServerAll');await page.evaluate(()=>{S.profile='other';});const count=await page.evaluate(()=>window.calls.length);
   await click('#batchServerSubmit');assert.equal(await page.evaluate(()=>window.calls.length),count);
   assert((await page.$eval('#batchServerError',n=>n.textContent)).includes('订阅已切换'));
   await page.evaluate(()=>closeModal());
  }
  // A failed server must not hide successful groups or erase their selections.
  await page.evaluate(async()=>{S.profile='clash';window.failLoad='server-2';await batchServerImport();});
  await click('#batchServersAll');await waitNodes(6);await page.waitForSelector('[data-batch-server-group="server-2"] .error');
  await click('#batchServerAll');assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),4);
  await page.evaluate(()=>{window.failLoad='';});await click('[data-batch-reload="server-2"]');await waitNodes(8);
  assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),4);
  await click('.batchServerSource[value="server-1"]');assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),0,'deselect clears only that server');
  await page.evaluate(()=>closeModal());
  // All-server loading stays bounded; unselected servers are never imported.
  await page.evaluate(async()=>{window.serverCount=6;window.maxActiveLoads=0;await batchServerImport();});
  await click('#batchServersAll');await waitNodes(12);assert.equal(await page.evaluate(()=>window.maxActiveLoads),3);
  await page.evaluate(()=>closeModal());
  // Global node limit and long names remain usable on a phone.
  await page.evaluate(async()=>{window.serverCount=1;window.manyNodes=true;await batchServerImport();});
  await click('#batchServersAll');await waitNodes(60);await click('#batchServerAll');
  assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),50);
  assert((await page.$eval('#batchServerError',n=>n.textContent)).includes('50'));
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await click('#batchNodesClear');assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),0);
  assert.deepEqual(errors,[]);console.log('PASS: multi-server grouping, duplicate inbound IDs, scoped chunks/retry, 3-worker loading, per-server failure recovery, 50-node cap; three desktop/mobile themes');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
