// Real Chromium checks with mock data only; no production servers or account access.
const puppeteer=require('puppeteer-core');
const fs=require('fs'),assert=require('assert'),path=require('path'),os=require('os'),http=require('http');
const {spawnSync}=require('child_process');
const captureDir=process.env.MXIOC_SCREENSHOT_DIR || path.join(os.tmpdir(),'mxioc-theme-previews');
fs.mkdirSync(captureDir,{recursive:true});
const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
const metrics={serverId:'demo',name:'Singapore Edge',managementIp:'198.51.100.24',hostname:'sg-edge-01',os:'Debian GNU/Linux 12',kernel:'6.1.0',cpuModel:'AMD EPYC Virtual Processor',cores:4,load:[.54,.38,.31],cpuPercent:26.8,perCpu:[0,1,2,3].map((x)=>({name:'cpu'+x,percent:20+x*5})),memory:{total:8589934592,used:3027959808,available:5561974784,percent:35.2,swapTotal:2147483648,swapUsed:0},network:{rxBytes:82678120448,txBytes:146884400128,rxBytesPerSecond:1954856,txBytesPerSecond:3484425},interfaces:[{name:'eth0',rxBytes:82678120448,txBytes:146884400128,rxBytesPerSecond:1954856,txBytesPerSecond:3484425}],summaryInterfaces:['eth0'],addresses:[{interface:'eth0',address:'10.0.0.24',family:'inet'},{interface:'eth0',address:'2001:db8::24',family:'inet6'}],disks:[{mount:'/',filesystem:'ext4',total:85899345920,used:28346784153,available:57552561767,percent:33}],sampledAt:1792684800,uptime:1284285,stale:false,warmingUp:false,error:''};
(async()=>{
const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN || '/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
let fixtureServer;
try{
 const qrCache=new Map();
 fixtureServer=http.createServer((req,res)=>{
  const route=new URL(req.url,'http://127.0.0.1');
  if(route.pathname==='/admin/api/qrcode'){
   const value=route.searchParams.get('url') || '';
   if(!qrCache.has(value)){
    const root=path.resolve(__dirname,'..'),local=path.join(root,'.venv','bin','python');
    const result=spawnSync(process.env.MXIOC_PYTHON_BIN || (fs.existsSync(local)?local:'python3'),['-c','import server,sys;sys.stdout.buffer.write(server.subscription_qr_svg(sys.argv[1]))',value],{cwd:root});
    if(result.status!==0){res.writeHead(500);res.end();return;}
    qrCache.set(value,result.stdout);
   }
   res.writeHead(200,{'Content-Type':'image/svg+xml'});res.end(qrCache.get(value));return;
  }
  res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(html);
 });
 await new Promise((resolve,reject)=>{fixtureServer.once('error',reject);fixtureServer.listen(0,'127.0.0.1',resolve);});
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 await page.setViewport({width:1440,height:1100,deviceScaleFactor:1});await page.goto('http://127.0.0.1:'+fixtureServer.address().port+'/admin/',{waitUntil:'domcontentloaded'});
 await page.evaluate((metrics)=>{
  S.profiles=[{id:'clash',name:'示例订阅',url:'/sub/demo'}];S.profile='clash';
  S.data={nodes:[{index:0,name:'Singapore Reality',type:'vless',server:'198.51.100.24',port:443,config:{name:'Singapore Reality',type:'vless',server:'198.51.100.24',port:443,uuid:'22453845-ff1a-471d-8214-25952a9348a6',tls:true,servername:'www.microsoft.com','reality-opts':{'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','short-id':'abcdef12'},'client-fingerprint':'chrome'}}],groups:[],rules:[],dnsPolicies:[],updated:'2026-10-22',profile:{name:'示例订阅',traffic:{configured:false,bindings:[]}}};
  api=async(path,opt)=>{if(path==='/servers')return {servers:[{id:'demo',name:'Singapore Edge',host:'198.51.100.24',installType:'sing-box',sshPort:22,sshUser:'root',fingerprint:'SHA256:'+'a'.repeat(43)}]};if(path.startsWith('/servers/metrics'))return metrics;if(path==='/snapshot')return S.data;if(path==='/failovers')return {failovers:[]};if(path==='/server-chains')return {chains:[]};if(path==='/conversions')return {formats:[{name:'电脑 v2rayN · Xray 主备配置',supported:1,unit:'主备组',available:true,note:'独立 JSON 订阅，按优先顺序切换并恢复切回；本地 SOCKS 10808。',url:'/convert/demo/v2rayn-ha'},{name:'安卓 v2rayNG 节点订阅',supported:3,unit:'节点',available:true,note:'流量与有效期通过订阅响应头提供；普通节点列表不含主备策略。',url:'/convert/demo/v2rayng'},{name:'小火箭主备 · 第一步：节点订阅',supported:2,unit:'节点',available:true,note:'先添加节点，再启用第二步策略配置。',url:'/convert/demo/shadowrocket-ha'},{name:'小火箭主备 · 第二步：策略配置',supported:1,unit:'主备组',available:true,note:'在配置页添加并启用此配置，不启用全局回退。',url:'/convert/demo/shadowrocket-config'}]};if(path==='/account')return {username:'admin'};if(path==='/backups')return {backups:[]};if(path==='/updates')return {available:false,currentSha:'abc123',checkedAt:metrics.sampledAt};if(path==='/raw')return {yaml:'proxies: []\nproxy-groups: []\nrules: []'};if(path.startsWith('/servers/inbounds'))return {inbounds:[],server:{id:'demo',name:'Singapore Edge',host:'198.51.100.24',installType:'sing-box'}};if(path==='/nodes/validate')return {config:JSON.parse(opt.body).config,uri:'vless://example'};throw Error('Unmocked '+path);};
  document.getElementById('boot').classList.add('hidden');document.getElementById('login').classList.add('hidden');document.getElementById('app').classList.remove('hidden');document.getElementById('currentProfileName').textContent='示例订阅';
  S.monitorId='demo';S.monitorHistory=new Map([['demo/auto',Array.from({length:30},(_,i)=>({time:metrics.sampledAt-150+i*5,rx:1200000+Math.sin(i/3)*700000+i*17000,tx:1800000+Math.cos(i/4)*900000+i*23000}))]]);
 },metrics);
 for(const theme of ['high','low','pink']){
  await page.evaluate(async theme=>{setTheme(theme);await go('monitoring');},theme);
  await page.waitForSelector('.monitor-grid');await page.evaluate(()=>stopMonitoring());await new Promise(r=>setTimeout(r,180));await page.screenshot({path:`${captureDir}/${theme}-monitoring.png`,fullPage:true});
  const style=await page.evaluate(()=>({body:getComputedStyle(document.body).backgroundColor,nav:getComputedStyle(document.querySelector('.nav .icon')).width,panel:getComputedStyle(document.querySelector('.panel')).backgroundColor}));
  console.log(theme,JSON.stringify(style));assert.equal(style.nav,'22px');
  if(theme==='pink')assert.equal(style.body,'rgb(251, 247, 244)');
  await page.evaluate(()=>nodeModal(0));
  await page.screenshot({path:`${captureDir}/${theme}-node.png`,fullPage:true});
  assert.equal(await page.$eval('#nRealityHybrid',n=>n.value),'');
  await page.select('#nRealityHybrid','false');
  assert(await page.$('#nodePreview'));await page.evaluate(async()=>{await document.getElementById('nodePreview').onclick();});assert(await page.$('#nodePreviewResult:not(.hidden)'));await page.evaluate(()=>closeModal());
 }
 for (const theme of ['high','low','pink']) {
  for (const route of ['overview','profiles','servers','nodes','chains','groups','rules','dns','subscriptions','traffic','raw','system','settings','maintenance']) {
   await page.evaluate(async({theme,route})=>{setTheme(theme);await go(route);},{theme,route});
   await new Promise(resolve=>setTimeout(resolve,35));
   const content=await page.$eval('#content',n=>n.textContent);
   assert(!content.includes('页面加载失败'),theme+'/'+route+': '+content);
   if (theme==='pink') {
    const dark=await page.evaluate(()=>[...document.querySelectorAll('#content .btn,#content input:not([type=checkbox]),#content select,#content textarea,#content th')].filter(n=>{
     const color=getComputedStyle(n).backgroundColor.match(/rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)/);
     return color && (!color[4] || +color[4]>.5) && Math.max(+color[1],+color[2],+color[3])<70;
    }).map(n=>n.outerHTML.slice(0,100)));
    assert.equal(dark.length,0,'Dark component leaked into pink '+route+': '+dark.join(','));
   }
  }
 }
 console.log('PASS: 42 page/theme combinations; no dark component leaked into pink controls');
 await page.setViewport({width:1440,height:1100,deviceScaleFactor:1});
 await page.evaluate(()=>{
  const base=S.data.nodes[0];
  S.data.nodes=[base,{...base,index:1,name:'备用入口',config:{...base.config,name:'备用入口',server:'198.51.100.25'}},{...base,index:2,name:'固定出口',config:{...base.config,name:'固定出口',server:'198.51.100.26'}}];
 });
 for (const theme of ['high','low','pink']) {
  await page.evaluate(async theme=>{setTheme(theme);await go('chains');await chains();await failoverModal();},theme);
  assert.equal(await page.$$eval('.foEntry',x=>x.length),2);
  assert.equal(await page.$eval('#foExit',x=>x.value),'固定出口');
  await page.click('#foAdd');assert.equal(await page.$$eval('.foEntry',x=>x.length),3);
  await page.screenshot({path:path.join(captureDir,theme+'-failover.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: prioritized multi-entry form in all three themes');
 for (const theme of ['high','low','pink']) {
  await page.evaluate(async theme=>{setTheme(theme);await profileClientLinks(encodeURIComponent('clash'));},theme);
  await page.waitForSelector('#clientConversionRows .subscription-row');
  await page.waitForFunction(()=>[...document.querySelectorAll('#clientConversionRows .subscription-qr')].every(img=>img.complete && img.naturalWidth>0));
  assert(!await page.$eval('#clientConversionRows',n=>n.textContent.includes('null/convert')));
  assert.equal(await page.$$eval('#clientConversionRows .subscription-row',x=>x.length),4);
  await page.screenshot({path:path.join(captureDir,theme+'-client-subscriptions.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: desktop, Android and Shadowrocket client links in all three themes');
 for (const theme of ['high','low','pink']) {
  await page.evaluate(theme=>{setTheme(theme);serverForm('',true);},theme);
  for (const kind of ['xray','sing-box']) {
   const state=await page.evaluate(kind=>{
    const select=document.getElementById('rsInstallType');
    const option=[...select.options].find(o=>o.value===kind);
    select.value=kind;select.onchange();
    return {disabled:option.disabled,hidden:document.getElementById('rsCoreBox').classList.contains('hidden'),panelRequired:document.getElementById('rsPanelPassword').required,note:document.getElementById('rsInstallNote').textContent};
   },kind);
   assert(!state.disabled && state.hidden && !state.panelRequired);
   assert(state.note.includes('不安装、不重启'));
  }
  await page.screenshot({path:path.join(captureDir,theme+'-existing-core.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: existing Xray and sing-box are selectable in every theme without installation fields');
 for (const theme of ['high','low','pink']) {
  await page.evaluate(theme=>{
   setTheme(theme);serverForm('',true);
   const type=document.getElementById('rsInstallType');type.value='x-panel';type.onchange();
   document.getElementById('rsPanelAddress').value='https://panel.example.com:13145/riben/';
  },theme);
  assert.equal(await page.$eval('#rsMode',n=>n.value),'url');
  assert(await page.$eval('#rsPanelUserLabel',n=>n.textContent.includes('X-Panel')));
  assert(await page.$eval('#rsPanelPasswordLabel',n=>n.textContent.includes('X-Panel')));
  assert(await page.$eval('#rsDomainBox',n=>n.classList.contains('hidden')));
  assert(await page.$eval('#rsPanelAddress',n=>n.required && !n.disabled));
  await page.screenshot({path:path.join(captureDir,theme+'-existing-panel-url.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: complete existing-panel URL and X-Panel credential labels in all themes');
 for (const theme of ['high','low','pink']) {
  await page.evaluate(async theme=>{setTheme(theme);await go('nodes');await chooseNodeServer('browse');},theme);
  await page.waitForSelector('#pickerOpen');await page.click('#pickerOpen');
  await page.waitForFunction(()=>S.page==='serverNodes' && document.getElementById('content').textContent.includes('返回总控节点'));
  await page.evaluate(()=>{
   S.remoteRows=[{id:1,port:24443,remark:'订阅专属 Reality',protocol:'vless',enable:true,up:1024,down:2048,shareLinks:['vless://example#demo']},
    {id:2,port:443,remark:'共用入站',protocol:'vless',enable:true,shareLinks:['vless://a','vless://b']}];
   renderRemoteNodes();remoteNodeLinks(1);
   document.getElementById('remoteBindOnImport').checked=true;document.getElementById('remoteBindOnImport').onchange();
  });
  assert(await page.$eval('#remoteDedicated',n=>n.required));
  await page.screenshot({path:path.join(captureDir,theme+'-server-node-import.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: choose server, browse inbounds and dedicated subscription import in all themes');
 for (const theme of ['high','low','pink']) {
  await page.evaluate(async theme=>{
   setTheme(theme);S.data.profile.traffic={configured:true,enforce:true,upload:1024,download:2048,total:10737418240,used:3072,remaining:10737415168,percent:0,multiplier:2,rawUsed:1536,bindings:[{serverId:'demo',inboundId:1,port:24443,name:'订阅专属节点',status:'active',bandwidth:{uploadKbps:1000,downloadKbps:2000}}]};
   await go('traffic');nodeBandwidthModal('demo',1);
  },theme);
  assert.equal(await page.$eval('#trafficTotal',n=>n.value),'10');
  assert.equal(await page.$eval('#bandwidthUpload',n=>n.value),'1');
  assert.equal(await page.$eval('#bandwidthDownload',n=>n.value),'2');
  await page.screenshot({path:path.join(captureDir,theme+'-node-bandwidth.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: subscription quota and per-node bandwidth dialog in all three themes');
 await page.setViewport({width:390,height:844,deviceScaleFactor:1});
 for (const theme of ['high','low','pink']) {
  await page.evaluate(async theme=>{setTheme(theme);await go('monitoring');},theme);
  await page.waitForSelector('.monitor-grid');await page.evaluate(()=>stopMonitoring());
  await page.screenshot({path:path.join(captureDir,theme+'-mobile.png'),fullPage:true});
  const overflow=await page.evaluate(()=>({width:window.innerWidth,scroll:document.documentElement.scrollWidth}));
  assert(overflow.scroll<=overflow.width,'Unexpected mobile page overflow: '+theme);
  await page.evaluate(()=>nodeModal(0));
  const bounds=await page.$eval('.modalbox',n=>({width:n.getBoundingClientRect().width,screen:window.innerWidth}));
  assert(bounds.width<bounds.screen,'Mobile dialog too wide: '+theme);
  await page.evaluate(()=>closeModal());
  await page.evaluate(async()=>{await go('traffic');nodeBandwidthModal('demo',1);});
  const bandwidthBounds=await page.$eval('.modalbox',n=>({width:n.getBoundingClientRect().width,screen:window.innerWidth}));
  assert(bandwidthBounds.width<bandwidthBounds.screen,'Mobile bandwidth dialog too wide: '+theme);
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'Bandwidth page overflows mobile: '+theme);
  await page.screenshot({path:path.join(captureDir,theme+'-mobile-bandwidth.png'),fullPage:true});
  await page.evaluate(()=>closeModal());
 }
 console.log('PASS: all three mobile themes and node dialogs fit 390px viewport');
 await page.evaluate(async()=>{await go('settings');});
 assert.equal(await page.$$eval('[data-theme-choice]',x=>x.length),3);
 console.log('page errors',errors);assert.equal(errors.length,0);
}finally{await browser.close();if(fixtureServer)await new Promise(resolve=>fixtureServer.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;});
