// Real browser, mocked sampling/TLS only. Never contacts user servers.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.setViewport({width:1440,height:1000});await page.goto(`http://127.0.0.1:${server.address().port}/`);
  await page.evaluate(()=>{
   document.getElementById('boot').classList.add('hidden');document.getElementById('login').classList.add('hidden');document.getElementById('app').classList.remove('hidden');
   S.profiles=[{id:'clash',name:'test'}];S.data={nodes:[],groups:[],rules:[],profile:{name:'test'}};S.profile='clash';
   window.fixtureServers=Array.from({length:123},(_,i)=>({id:'s'+i,name:'Edge '+i,host:'198.51.100.'+(i%254+1),installType:'xray'}));
   window.activeSamples=0;window.maxSamples=0;window.sampleCalls=0;window.scanBatches=[];window.scanActive=0;window.maxScanActive=0;window.scanForces=[];
   api=async (url,opt)=>{
    if(url==='/servers')return {servers:fixtureServers};
    if(url.startsWith('/servers/metrics')){
     activeSamples++;maxSamples=Math.max(maxSamples,activeSamples);sampleCalls++;
     await new Promise(r=>setTimeout(r,20));activeSamples--;
     return {serverId:url.split('=')[1],cpuPercent:30,cores:4,load:[.1,.2,.3],memory:{percent:40,used:400,total:1000,swapUsed:0,swapTotal:0},network:{rxBytes:1,txBytes:2,rxBytesPerSecond:3,txBytesPerSecond:4},interfaces:[],summaryInterfaces:[],disks:[{mount:'/',percent:50,available:500,total:1000,used:500}],perCpu:[],addresses:[],uptime:600,sampledAt:1792700000,managementIp:'198.51.100.1',hostname:'edge',os:'Linux',kernel:'6',cpuModel:'CPU'};
    }
    if(url==='/servers/sni'){
     const body=JSON.parse(opt.body);scanBatches.push(body.candidates);scanForces.push(body.force);
     scanActive++;maxScanActive=Math.max(maxScanActive,scanActive);
     await new Promise(r=>setTimeout(r,30));scanActive--;
     return {results:body.candidates.map((domain,i)=>({domain,ok:i!==0,realityVerified:i!==0,verifiedAddress:'8.8.8.8',latencyMs:90-i,tls:'TLSv1.3',alpn:'h2',error:'unavailable'}))};
    }
    throw Error('unexpected request '+url);
   };
   S.monitorId='';void go('monitoring');
  });
  await page.waitForFunction(()=>document.querySelectorAll('.host-card').length===18 && sampleCalls===18 && activeSamples===0);
  if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,'monitor-overview.png')});}
  assert.equal(await page.$('#monitorHost'),null);assert((await page.evaluate(()=>maxSamples))<=3);
  await page.click('.host-card');await page.waitForSelector('.monitor-grid');
  await page.click('[data-page="monitoring"]');await page.waitForSelector('.host-overview-grid');
  await page.type('#search','Edge 122');await page.waitForFunction(()=>document.querySelectorAll('.host-card').length===1);
  await page.evaluate(()=>{stopMonitoring();S.serverId='s1';S.remoteServer={installType:'xray'};remoteNodeForm(true);document.getElementById('rnName').value='Preserved relay';document.getElementById('rnLanding').value='ss://preserved';});
  if(process.env.MXIOC_SCREENSHOT_DIR)await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,'relay-form.png')});
  await page.click('#rnSniTest');await page.waitForFunction(()=>document.getElementById('sniScanProgress')?.value===100);
  const batches=await page.evaluate(()=>scanBatches);assert.equal(batches.flat().length,42);assert.equal(batches.length,3);assert(batches.every(b=>b.length===14));
  assert.equal(await page.evaluate(()=>maxScanActive),2);
  assert.deepEqual(await page.evaluate(()=>scanForces),[false,false,false]);
  await page.click('#sniRescan');await page.waitForFunction(()=>document.getElementById('sniScanProgress')?.value===100);
  assert.deepEqual(await page.evaluate(()=>scanForces.slice(-3)),[true,true,true]);
  assert(await page.$eval('#sniScanResults button:disabled',el=>el.disabled));
  const selected=await page.$eval('#sniScanResults button:not(:disabled)',el=>el.dataset.sniDomain);
  await page.click('#sniScanResults button:not(:disabled)');assert.equal(await page.$('#sniScanner'),null);
  assert.equal(await page.$eval('#rnSni',el=>el.value),selected);assert.equal(await page.$eval('#rnName',el=>el.value),'Preserved relay');
  assert.equal(await page.$eval('#rnSni',el=>el.dataset.sniAddress),'8.8.8.8');
  await page.click('#rnSniTest');await page.keyboard.press('Escape');assert.equal(await page.$('#sniScanner'),null);assert(await page.$('#modal:not(.hidden)'));
  for(const theme of ['high','low','pink']){
   await page.setViewport({width:390,height:844});await page.evaluate(theme=>setTheme(theme),theme);
   await page.click('#rnSniTest');await page.waitForFunction(()=>document.getElementById('sniScanProgress')?.value===100);
   assert(await page.$eval('#sniScanner',el=>el.getBoundingClientRect().width<=innerWidth));
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,theme+'-sni-scanner.png')});}
   await page.click('#sniCancel');
  }
  await page.evaluate(()=>{closeModal();S.monitorId='';S.filters.monitoring='';void monitoring();});
  await page.waitForSelector('.host-overview-grid');
  assert.equal(await page.$$eval('.host-card',cards=>cards.length),18);
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.evaluate(()=>stopMonitoring());
  const missing=await page.evaluate(()=>[...document.querySelectorAll('use')].map(el=>el.getAttribute('href')).filter(ref=>!document.querySelector(ref)));
  assert.deepEqual(missing,[]);assert.deepEqual(errors,[]);
  console.log('PASS: paginated monitor cards, 3-worker sampling, detail/back/search; curated 42 SNI candidates, three batches, selection, retained form, cancellation, three mobile themes and SVG icon references');
 } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
