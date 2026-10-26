// Real Chromium forms with mock persistence; no production servers or credentials.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const fixture=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(resolve=>fixture.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:'+fixture.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.profile='clash';S.page='nodes';S.profiles=[{id:'clash',name:'test'}];
   S.data={nodes:[],groups:[],rules:[],profile:{name:'test',traffic:{configured:false,bindings:[]}}};window.sent=[];
   api=async(url,opt)=>{
    if(url==='/snapshot')return S.data;
    if(url==='/nodes'){
     const config=JSON.parse(opt.body).config;window.sent.push(config);
     S.data.nodes=[{index:0,name:config.name,type:config.type,server:config.server,port:config['port-range']||config.port,config}];
     return {ok:true};
    }
    throw Error('unexpected request '+url);
   };
  });
  for(const theme of ['high','low','pink'])for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(theme=>{
    setTheme(theme);S.data.nodes=[{index:0,name:'Mieru test',config:{name:'Mieru test',type:'mieru',server:'example.com',port:2999,username:'user',password:'test-password',transport:'TCP',udp:true}}];nodeModal(0);
   },theme);
   assert.equal(await page.$eval('#nMieruUsername',n=>n.value),'user');
   await page.select('#nMieruTransport','UDP');
   await page.type('#nMieruRange','2090-2099');
   assert(await page.$eval('#nPort',n=>n.disabled&&!n.required));
   await page.select('#nMieruHandshake','HANDSHAKE_NO_WAIT');
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   if(process.env.MXIOC_SCREENSHOT_DIR){fs.mkdirSync(process.env.MXIOC_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.MXIOC_SCREENSHOT_DIR,theme+'-mieru-'+width+'.png'),fullPage:true});}
   await page.$eval('#nodeSave',n=>n.scrollIntoView({block:'center'}));
   assert.equal(await page.$eval('#nodeSave',n=>{const r=n.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.id;}),'nodeSave');
   await page.click('#nodeSave');await page.waitForSelector('#modal.hidden',{timeout:4000});
   const config=await page.evaluate(()=>sent.at(-1));
   assert.equal(config['port-range'],'2090-2099');assert.equal(config.transport,'UDP');assert(!Object.hasOwn(config,'port'));
   assert.equal(config['handshake-mode'],'HANDSHAKE_NO_WAIT');assert.equal(config.password,'test-password');
   await page.evaluate(()=>nodeModal(0));
   await page.$eval('#nMieruRange',n=>{n.value='';n.dispatchEvent(new Event('input',{bubbles:true}));});
   await page.$eval('#nPort',n=>{n.value='3001';});await page.click('#nodeSave');await page.waitForSelector('#modal.hidden');
   assert.equal(await page.evaluate(()=>sent.at(-1).port),3001);assert(!await page.evaluate(()=>Object.hasOwn(sent.at(-1),'port-range')));
  }
  assert.deepEqual(errors,[]);console.log('PASS: real Chromium Mieru edits in all themes, desktop/mobile, TCP/UDP, range/single-port switching and payload preservation');
 }finally{await browser.close();await new Promise(resolve=>fixture.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
