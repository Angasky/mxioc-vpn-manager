// Real Chromium UI with mock persistence; no production servers, credentials or SSH.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const fixture=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(r=>fixture.listen(0,'127.0.0.1',r));
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
     const config=JSON.parse(opt.body).config;sent.push(config);
     S.data.nodes=[{index:0,name:config.name,type:config.type,server:config.server,port:config.port,config}];
     return {ok:true};
    }
    throw Error('unexpected request '+url);
   };
  });
  for(const theme of ['high','low','pink'])for(const width of [1440,390]){
   await page.setViewport({width,height:1000});
   await page.evaluate(theme=>{
    setTheme(theme);S.data.nodes=[{index:0,name:'Snell test',config:{name:'Snell test',type:'snell',server:'example.com',port:24443,psk:' secret PSK ',version:4,udp:true,reuse:true,'obfs-opts':{mode:'http',host:'bing.com'}}}];nodeModal(0);
   },theme);
   assert.equal(await page.$eval('#nSnellPsk',el=>el.value),' secret PSK ');
   await page.select('#nSnellVersion','1');
   assert(await page.$eval('#nUdp',el=>el.disabled&&!el.checked));
   assert(await page.$eval('#nSnellReuse',el=>el.disabled&&!el.checked));
   await page.select('#nSnellVersion','5');
   await page.click('#nSnellReuse');
   await page.select('#nSnellMode','shadow-tls');
   assert(!(await page.$eval('#nSnellPasswordBox',el=>el.classList.contains('hidden'))));
   await page.$eval('#nSnellPassword',el=>el.value=' obfs secret ');
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   await page.$eval('#nodeSave',el=>el.scrollIntoView({block:'center'}));
   assert.equal(await page.$eval('#nodeSave',el=>{const r=el.getBoundingClientRect();return document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.id;}),'nodeSave',`${theme}/${width}: save button covered`);
   await page.click('#nodeSave');await page.waitForSelector('#modal.hidden',{timeout:4000});
   const saved=await page.evaluate(()=>sent.at(-1));
   assert.equal(saved.version,5);assert.equal(saved.psk,' secret PSK ');assert.equal(saved.reuse,true);
   assert.equal(saved['obfs-opts'].password,' obfs secret ');assert.equal(saved['obfs-opts'].version,3);
   assert.deepEqual(saved['obfs-opts'].alpn,['h2']);
   await page.evaluate(()=>nodeModal(0));await page.select('#nSnellMode','');
   await page.$eval('#nodeSave',el=>el.scrollIntoView({block:'center'}));
   await page.click('#nodeSave');await page.waitForSelector('#modal.hidden',{timeout:4000});
   assert(!await page.evaluate(()=>Object.hasOwn(sent.at(-1),'obfs-opts')));
  }
  await page.evaluate(()=>nodeModal(null));await page.select('#nType','snell');
  assert.equal(await page.$('#nUuid'),null);assert(await page.$('#nSnellPsk'));
  assert.equal(await page.$eval('#nSnellVersion',el=>el.value),'4');
  assert.deepEqual(errors,[]);
  console.log('PASS: Snell create/edit, exact PSK preservation, v1/v5 UDP/reuse controls, ShadowTLS options, obfs removal, three desktop/mobile themes');
 }finally{await browser.close();await new Promise(r=>fixture.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1;});
