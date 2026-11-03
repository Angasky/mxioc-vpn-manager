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
    $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.page='serverNodes';S.profile='p0';S.serverId='server';S.profiles=Array.from({length:100},(_,i)=>({id:'p'+i,name:'订阅-'+i}));S.remoteRows=[{id:1,protocol:'hysteria',port:24443,remark:'HY2',enable:true,shareLinks:[]},{id:2,protocol:'vless',port:24444,remark:'VLESS',enable:true,shareLinks:[]}];S.data={profile:{name:'订阅-0',traffic:{bindings:[]}}};S.remoteServer={name:'测试服务器',host:'198.51.100.1'};S.remoteNodeSelection=new Set();S.remoteNodeSelectionServer='server';
    window.calls=[];window.failOnce=true;window.completed=new Map([['p0',new Set([1,2])],['p1',new Set([1])],['p3',new Set([1,2])]]);reload=async()=>{};
    api=async(url,options)=>{
     if(url==='/servers/users/targets')return {profiles:S.profiles.map(p=>({...p,importedInboundIds:[...(completed.get(p.id)||[])]}))};
     if(url!='/servers/users/batch')throw Error('unsafe endpoint '+url);
     const body=JSON.parse(options.body),profile=options.headers['X-Profile'];calls.push({profile,body});await new Promise(resolve=>setTimeout(resolve,30));
     return {results:body.inboundIds.map(id=>{const ok=!(failOnce&&profile==='p1');if(ok){if(!completed.has(profile))completed.set(profile,new Set());completed.get(profile).add(id);}return {inboundId:id,ok,added:ok?1:0,error:ok?'':'模拟断线，身份待核对'};})};
    };
    renderRemoteNodes();
   });
   await page.click('.remoteNodeChoice[value="1"]');await page.click('.remoteNodeChoice[value="2"]');await page.click('#remoteBatchImport');await page.waitForSelector('#sharedProfileList');
   assert.equal(await page.$('.sharedProfileChoice[value="p0"]'),null,'fully imported current subscription not hidden');
   assert.equal(await page.$('.sharedProfileChoice[value="p3"]'),null);
   assert.equal(await page.$eval('#sharedProfileList',n=>n.getBoundingClientRect().height<=281),true);
   await page.click('.sharedProfileChoice[value="p1"]');await page.click('.sharedProfileChoice[value="p2"]');await page.click('#sharedUserSave');await page.waitForFunction(()=>!$('sharedUserSave').disabled);
   assert.deepEqual(await page.evaluate(()=>calls.map(x=>[x.profile,x.body.inboundIds])),[['p1',[2]],['p2',[1,2]]]);
   assert(await page.$eval('.sharedProfileChoice[value="p2"]',n=>n.closest('label').hidden));
   await page.evaluate(()=>{failOnce=false});await page.click('#sharedUserSave');await page.waitForFunction(()=>$('sharedUserSave').disabled&&$('sharedUserProgress').textContent.includes('失败 0'));
   assert.deepEqual(await page.evaluate(()=>calls.map(x=>[x.profile,x.body.inboundIds])),[['p1',[2]],['p2',[1,2]],['p1',[2]]]);
   assert.equal(await page.evaluate(()=>calls.every(x=>x.body.serverId==='server'&&!('links'in x.body))),true);
   await page.type('#sharedProfileSearch','订阅-99');assert.equal(await page.$$eval('.shared-profile',nodes=>nodes.filter(n=>!n.hidden).length),1);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),true);
   await page.evaluate(()=>closeModal());await page.evaluate(()=>remoteNodeLinks(1));await page.waitForSelector('#sharedUserForm');
   assert.equal(await page.$('.sharedProfileChoice[value="p1"]'),null,'persisted completed import not hidden on reopen');
   await page.evaluate(()=>closeModal());
  }
  assert.deepEqual(errors,[]);console.log('PASS: server node multi/single selection, multi/single subscriptions, hidden completed targets, partial matrix imports and retry, desktop/mobile');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exit(1)});
