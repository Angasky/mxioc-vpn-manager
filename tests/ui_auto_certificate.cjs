const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN,headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});await new Promise(r=>host.listen(0,'127.0.0.1',r));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto('http://127.0.0.1:'+host.address().port+'/');
  async function setup(mode='success'){
   await page.evaluate(mode=>{
    $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.profile='owned-profile';S.serverId='server';S.page='nodes';S.remoteRows=[];S.remoteServer={installType:'3x-ui',certificateDomains:['node.example.com']};window.calls=[];
    notice=()=>{};reload=async()=>{};
    api=async(url,opt={})=>{calls.push({url,body:opt.body&&JSON.parse(opt.body),headers:opt.headers});if(url==='/servers/certificates')return {job:{id:'job',status:mode==='fail'?'failed':mode==='cancel'?'queued':'succeeded',domain:'node.example.com',error:'TCP 80 已被占用'}};if(url.startsWith('/servers/certificates?'))return {job:{id:'job',status:'succeeded',domain:'node.example.com'}};if(url==='/servers/users')return {shareLinks:['redacted'],inbound:{id:1}};throw Error(url);};
    remoteNodeForm(false);
   },mode);
  }
  for(const width of [1440,390]){
   await page.setViewport({width,height:1000});await setup();
   assert.equal(await page.$eval('#rnSniTest',e=>!e.classList.contains('hidden')),true);
   assert.ok(await page.evaluate(()=>sniCandidates().length>=42));
   await page.select('#rnTemplate','hysteria2');
   assert.equal(await page.$eval('#rnSni',e=>e.value),'node.example.com');
   assert.equal(await page.$eval('#rnSniTest',e=>e.classList.contains('hidden')),true);
   assert.equal(await page.$eval('#rnCertMode',e=>e.value),'auto');
   assert.equal(await page.$eval('#rnManualCertFields',e=>e.classList.contains('hidden')),true);
   await page.select('#rnCertMode','manual');assert.equal(await page.$eval('#rnCert',e=>e.required),true);
   await page.select('#rnCertMode','auto');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users'));
   const call=await page.evaluate(()=>calls.find(x=>x.url==='/servers/users'));assert.equal(call.body.certificateJobId,'job');assert.equal(call.headers['X-Profile'],'owned-profile');
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),true);
  }
  await setup('fail');await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>$('remoteError').textContent.includes('TCP 80'));
  assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/users')),false);
  await setup('cancel');await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>calls.length>0);await page.evaluate(()=>closeModal());await new Promise(r=>setTimeout(r,1800));
  assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/users')),false);
  assert.deepEqual(errors,[]);console.log('Auto certificate UI: modes, owned SNI, Reality candidates, scoped creation, failure and cancel PASS');
 }finally{await browser.close();await new Promise(r=>host.close(r));}
})().catch(e=>{console.error(e);process.exit(1)});
