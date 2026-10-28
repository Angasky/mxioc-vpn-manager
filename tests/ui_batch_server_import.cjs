// Real Chromium with mocked API: batch selection, progress, retry and profile isolation.
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
   window.calls=[];window.failOnce=true;window.created=new Set();
   api=async(url,opt)=>{
    if(url==='/snapshot')return S.data;
    if(url==='/servers')return {servers:[{id:'server-1',name:'测试服务器',host:'198.51.100.1',installType:'x-panel'}]};
    if(url.startsWith('/servers/inbounds?'))return {inbounds:[1,2,3,4,5,6].map(id=>({id,port:24000+id,remark:'服务器节点-'+id,protocol:id===5?'shadowsocks':'vless',enable:id!==6}))};
    if(url==='/servers/users/batch'){
     const body=JSON.parse(opt.body);window.calls.push({body,profile:opt.headers['X-Profile']});
     const results=body.inboundIds.map(inboundId=>{
      if(window.failOnce && inboundId===2)return {inboundId,ok:false,error:'连接超时，绑定待核对'};
      const existing=window.created.has(inboundId)?1:0;window.created.add(inboundId);return {inboundId,ok:true,added:1-existing,existing};
     });
     return {results,traffic:{configured:true,enforce:true,bindings:[],total:1024**3,expire:2000000000,upload:123,download:456}};
    }
    throw Error('unexpected '+url);
   };
  });
  for(const theme of ['high','low','pink'])for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(async theme=>{S.profile='clash';S.page='nodes';window.failOnce=true;window.calls=[];setTheme(theme);await batchServerImport();},theme);
   await page.click('#batchServerLoad');await page.waitForSelector('#batchServerAll');
   assert.equal(await page.$$eval('.batchServerChoice:disabled',nodes=>nodes.length),2);
   await page.click('#batchServerAll');assert.equal(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.length),4);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,theme+'-batch-'+width+'.png'),fullPage:true});}
   await page.$eval('#batchServerSubmit',n=>n.scrollIntoView({block:'center'}));await page.click('#batchServerSubmit');
   await page.waitForFunction(()=>$('batchServerProgress')?.textContent.includes('已处理 4 / 4'));
   assert((await page.$eval('#batchServerProgress',n=>n.textContent)).includes('成功 3，失败 1'));
   assert.deepEqual(await page.evaluate(()=>window.calls.map(x=>x.body.inboundIds)),[[1,2,3],[4]]);
   assert((await page.evaluate(()=>window.calls)).every(x=>x.profile==='clash'));
   assert.deepEqual(await page.$$eval('.batchServerChoice:checked',nodes=>nodes.map(n=>Number(n.value))),[2]);
   await page.evaluate(()=>{window.failOnce=false;});await page.click('#batchServerSubmit');
   await page.waitForFunction(()=>$('batchServerProgress')?.textContent.includes('成功 1，失败 0'));
   assert.deepEqual(await page.evaluate(()=>window.calls.at(-1).body.inboundIds),[2]);
   assert.equal(await page.evaluate(()=>S.data.profile.traffic.upload),123);
   await page.click('#batchServerAll');await page.evaluate(()=>{S.profile='other';});const count=await page.evaluate(()=>window.calls.length);
   await page.click('#batchServerSubmit');assert.equal(await page.evaluate(()=>window.calls.length),count);
   assert((await page.$eval('#batchServerError',n=>n.textContent)).includes('订阅已切换'));
   await page.evaluate(()=>closeModal());
  }
  assert.deepEqual(errors,[]);console.log('PASS: batch server selection, protocol/disabled guards, 3-item progress, partial success/retry, profile isolation; three desktop/mobile themes');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
