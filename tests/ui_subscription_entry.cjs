const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN,headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});await new Promise(r=>host.listen(0,'127.0.0.1',r));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto('http://127.0.0.1:'+host.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.profile='p0';S.page='nodes';S.serverId='unrelated';S.remoteRows=[{id:1,protocol:'hysteria',port:12345,remark:'wrong server'}];S.profiles=[{id:'p0',name:'当前订阅'},{id:'p1',name:'目标订阅'}];
   S.data={nodes:[{index:0,name:'HY2',type:'hysteria2',server:'node.example.com',port:24443,config:{name:'HY2',type:'hysteria2',password:'test-password'}}],groups:[],rules:[],dnsPolicies:[],profile:{name:'当前订阅',traffic:{configured:false,bindings:[{scope:'user',status:'active',serverId:'owned-server',inboundId:7,port:24443,importedNames:['HY2']}]}}};
   cards=()=>'';reload=async()=>{};window.calls=[];
   api=async(url,opt={})=>{calls.push({url,body:opt.body&&JSON.parse(opt.body),headers:opt.headers});if(url.startsWith('/servers/inbounds?'))return {server:{host:'node.example.com'},inbounds:[{id:7,protocol:'hysteria',port:24443,enable:true,remark:'HY2',settings:{clients:[{auth:'test-password',enable:true}]}}]};if(url==='/servers/users/batch')return {results:[{inboundId:7,ok:true,added:1}]};throw Error('unexpected '+url)};
   nodes();
  });
  assert.equal(await page.$$eval('.node-card-actions button',list=>list.filter(x=>x.textContent==='批量加入订阅').length),1);
  await page.click('button[onclick="nodeSubscriptionImport(0)"]');await page.waitForSelector('#sharedProfileList');
  assert.equal(await page.evaluate(()=>calls[0].url),'/servers/inbounds?id=owned-server');
  await page.click('.sharedProfileChoice[value="p0"]');await page.click('.sharedProfileChoice[value="p1"]');await page.click('#sharedUserSave');await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users/batch'));
  const call=await page.evaluate(()=>calls.find(x=>x.url==='/servers/users/batch'));assert.equal(call.body.serverId,'owned-server');assert.deepEqual(call.body.inboundIds,[7]);assert.equal(call.headers['X-Profile'],'p1');assert.ok(!('links' in call.body));
  await page.evaluate(()=>{closeModal();S.data.nodes[0].config.password='manually-changed';nodes();});await page.click('button[onclick="nodeSubscriptionImport(0)"]');await page.waitForFunction(()=>$('nodeSubscriptionError')?.textContent.includes('不一致'));
  assert.equal(await page.evaluate(()=>calls.filter(x=>x.url==='/servers/users/batch').length),1);
  await page.evaluate(()=>{S.remoteRows=[{id:7,protocol:'hysteria',remark:'HY2',port:24443}];sharedUserPicker();});assert.equal(await page.$eval('#sharedInbound',select=>select.options.length),1);
  assert.deepEqual(errors,[]);console.log('Batch subscription entry: node card, source isolation, credential check and HY2 picker PASS');
 }finally{await browser.close();await new Promise(r=>host.close(r));}
})().catch(e=>{console.error(e);process.exit(1)});
