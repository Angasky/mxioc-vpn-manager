const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});await new Promise(resolve=>host.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',error=>errors.push(String(error)));await page.goto('http://127.0.0.1:'+host.address().port+'/');
  for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(()=>{
    $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.profile='p0';S.serverId='server';S.profiles=Array.from({length:100},(_,i)=>({id:'p'+i,name:'订阅-'+i}));S.remoteRows=[{id:1,protocol:'hysteria',port:443,remark:'HY2',shareLinks:['do-not-copy-original']}];S.data={profile:{name:'订阅-0'}};
    window.calls=[];window.failOnce=true;reload=async()=>{};
    api=async(url,options)=>{if(url!='/servers/users/batch')throw Error('unsafe endpoint '+url);const body=JSON.parse(options.body);window.calls.push({profile:options.headers['X-Profile'],body});await new Promise(resolve=>setTimeout(resolve,40));const ok=!(window.failOnce&&options.headers['X-Profile']==='p1');return {results:[{inboundId:1,ok,added:ok?1:0,error:ok?'':'模拟断线，身份待核对'}]};};
    remoteNodeLinks(1);
   });
   assert.equal(await page.$eval('#sharedProfileList',n=>n.getBoundingClientRect().height<=321),true);
   await page.click('.sharedProfileChoice[value="p1"]');await page.click('#sharedUserSave');await page.waitForFunction(()=>!$('sharedUserSave').disabled);
   assert.deepEqual(await page.evaluate(()=>calls.map(x=>x.profile)),['p0','p1']);
   assert.equal(await page.$eval('.sharedProfileChoice[value="p0"]',n=>n.disabled),true);
   await page.evaluate(()=>{window.failOnce=false;});await page.click('#sharedUserSave');await page.waitForFunction(()=>$('sharedUserSave').disabled&&$('sharedUserProgress').textContent.includes('2 份'));
   assert.deepEqual(await page.evaluate(()=>calls.map(x=>x.profile)),['p0','p1','p1']);
   assert.equal(await page.evaluate(()=>calls.every(x=>x.body.serverId==='server'&&x.body.inboundIds.length===1&&x.body.inboundIds[0]===1&&!('links' in x.body))),true);
   await page.type('#sharedProfileSearch','订阅-99');assert.equal(await page.$$eval('.shared-profile',nodes=>nodes.filter(n=>getComputedStyle(n).display!=='none').length),1);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),true);await page.evaluate(()=>closeModal());
  }
  assert.deepEqual(errors,[]);console.log('multi-subscription HY2: bounded list, independent profile requests, partial retry, desktop/mobile PASS');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exit(1);});
