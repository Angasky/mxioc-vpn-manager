// Real Chromium + mocked API: shared-user forms, isolation and theme layouts.
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
   S.serverId='server-1';S.remoteServer={name:'测试服务器',host:'198.51.100.1',installType:'x-panel'};
   S.remoteRows=[{id:7,port:443,protocol:'vless',remark:'Reality 共用入口',shareLinks:['vless://test'],enable:true}];
   window.sent=[];window.failUser=false;
   api=async(url,opt)=>{
    if(url==='/snapshot')return S.data;
    if(url==='/servers/users'){
     window.sent.push({payload:JSON.parse(opt.body),profile:opt.headers['X-Profile']});
     if(window.failUser)throw Error('远端用户接口暂不可用，请重试');
     return {ok:true,added:1,bound:true};
    }
    throw Error('unexpected request '+url);
   };
  });
  for(const theme of ['high','low','pink'])for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(theme=>{S.profile='clash';S.page='nodes';setTheme(theme);sharedUserPicker();},theme);
   assert(await page.$('#sharedChoose'));await page.click('#sharedChoose');
   assert(await page.$('#sharedUserForm'));assert(!await page.$('#remoteDedicated'));
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,theme+'-shared-user-'+width+'.png'),fullPage:true});}
   await page.click('#sharedUserSave');await page.waitForSelector('#modal.hidden');
   const sent=await page.evaluate(()=>window.sent.at(-1));assert.deepEqual(sent,{payload:{serverId:'server-1',inboundId:7},profile:'clash'});
   await page.evaluate(()=>{window.failUser=true;remoteNodeLinks(7);});await page.click('#sharedUserSave');
   await page.waitForFunction(()=>$('sharedUserError')?.textContent.includes('重试'));
   assert(!await page.$eval('#sharedUserSave',n=>n.disabled));
   const before=await page.evaluate(()=>window.sent.length);
   await page.evaluate(()=>{S.profile='other';});await page.click('#sharedUserSave');
   assert.equal(await page.evaluate(()=>window.sent.length),before);
   await page.evaluate(()=>{S.profile='clash';window.failUser=false;closeModal();
    S.data.profile.traffic.bindings=[{scope:'user',userEmail:'mxioc-test-user',name:'共用 Reality',serverId:'server-1',inboundId:7,port:443,status:'active',counterSource:'authenticated-client'}];
    $('content').innerHTML=trafficBindings(S.data.profile.traffic);
   });
   const speed=await page.$('button[onclick^="nodeBandwidthModal"]');assert(await speed.evaluate(n=>n.disabled));
   assert((await page.$eval('#content',n=>n.textContent)).includes('独立用户'));
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  }
  assert.deepEqual(errors,[]);console.log('PASS: shared-user creation, scoped profile, retry/error handling, bandwidth guards; three themes on desktop/mobile');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
