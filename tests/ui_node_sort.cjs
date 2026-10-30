// Real browser pointer sorting with local fixtures; no production subscriptions.
const puppeteer = require('puppeteer-core');
const fs = require('fs'), path = require('path'), http = require('http'), assert = require('assert/strict');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
  const browser = await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN || '/usr/bin/chromium',headless:true,args:['--no-sandbox']});
  const html = fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
  const fixture = http.createServer((req,res) => { res.setHeader('Content-Type','text/html; charset=utf-8'); res.end(html); });
  await new Promise(resolve => fixture.listen(0,'127.0.0.1',resolve));
  try {
    const page = await browser.newPage(), errors = [];
    page.on('pageerror', error => errors.push(String(error)));
    await page.goto('http://127.0.0.1:' + fixture.address().port);
    await page.evaluate(() => {
      $('boot').classList.add('hidden'); $('login').classList.add('hidden'); $('app').classList.remove('hidden');
      S.profile = 'test'; S.page = 'nodes'; S.profiles = [{id:'test',name:'test'}];
      window.sent = []; window.failSave = false;
      window.resetNodes = () => {
        S.nodeSelection.clear();
        S.filters.nodes = '';
        S.data = {nodes:Array.from({length:120},(_,index) => ({index,name:'Node ' + String(index+1).padStart(3,'0'),type:'snell',server:'node.example.com',port:20000+index,config:{type:'snell',version:4,udp:true}})),groups:[],rules:[],dnsPolicies:[],profile:{name:'test',traffic:{configured:false,bindings:[]}}};
        nodes();
      };
      api = async (url,opt) => {
        if (url === '/nodes/group-options') return {groups:['Proxy','Cloudflare']};
        if (url === '/nodes/groups') {
          window.membership = JSON.parse(opt.body);
          return {ok:true};
        }
        if (url === '/snapshot') return S.data;
        if (url === '/nodes/move') {
          const data = JSON.parse(opt.body); sent.push(data);
          await new Promise(resolve => setTimeout(resolve,40));
          if (failSave) throw Error('test save rejected');
          const index = S.data.nodes.findIndex(node => node.name === data.name);
          const [node] = S.data.nodes.splice(index,1);
          const target = S.data.nodes.findIndex(node => node.name === data.targetName);
          S.data.nodes.splice(target+(data.position === 'after' ? 1 : 0),0,node);
          S.data.nodes.forEach((node,index) => node.index = index);
          return {ok:true};
        }
        throw Error('Unexpected request ' + url);
      };
      resetNodes();
    });
    await page.evaluate(() => go('nodes'));
    const names = () => page.$$eval('#nodeRows > .node-card', cards => cards.map(card => card.dataset.nodeName));
    const saved = () => page.waitForFunction(() => !S.nodeOrderSaving && $('nodeSortStatus').textContent.includes('已保存'));
    const beginLast = async () => {
      await page.$eval('#nodeRows > .node-card:last-child .drag-handle', el => el.scrollIntoView({block:'center'}));
      const handle = await page.$('#nodeRows > .node-card:last-child .drag-handle');
      const box = await handle.boundingBox();
      await page.mouse.move(box.x+box.width/2,box.y+box.height/2); await page.mouse.down();
      await page.mouse.move(box.x+box.width/2-12,box.y+box.height/2-12,{steps:3});
      return box;
    };
    for (const theme of ['high','low','pink']) {
      await page.setViewport({width:1440,height:900});
      await page.evaluate(theme => { setTheme(theme); resetNodes(); },theme);
      assert.equal((await names()).length,120,'all nodes available without page barriers');
      const requestCount = await page.evaluate(() => sent.length);
      const box = await beginLast();
      await page.mouse.move(box.x,8,{steps:5});
      await pause(150); const firstScroll = await page.evaluate(() => scrollY);
      await pause(400); const secondScroll = await page.evaluate(() => scrollY);
      assert(secondScroll < firstScroll-100,'stationary pointer continues scrolling upwards');
      await page.waitForFunction(() => scrollY === 0,{timeout:12000});
      const target = await page.$eval('#nodeRows > .node-card:not(.dragging)', el => { const r=el.getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2}; });
      await page.mouse.move(target.x,target.y,{steps:3}); await pause(50); await page.mouse.up(); await saved();
      assert.equal((await names())[0],'Node 120');
      assert.equal(await page.evaluate(() => sent.length),requestCount+1,'one save per drag');
      await page.evaluate(() => resetNodes());
      const original = await names(); await beginLast();
      await page.mouse.move(700,40,{steps:3}); await pause(150); await page.keyboard.press('Escape'); await page.mouse.up();
      assert.deepEqual(await names(),original,'Escape restores original order');
      assert.equal(await page.$('.node-drag-ghost'),null);
      assert.equal(await page.evaluate(() => document.body.classList.contains('node-drag-active')),false);
      await page.evaluate(() => { window.scrollTo(0,0); nodePositionModal(119); });
      await page.$eval('#nodePosition',el => el.value='1'); await page.click('#nodePositionForm button'); await saved();
      assert.equal((await names())[0],'Node 120','absolute position works across former page boundary');
      await page.evaluate(() => { resetNodes(); S.filters.nodes='Node 01'; nodes(); nodePositionModal(119); });
      await page.$eval('#nodePosition',el => el.value='5'); await page.click('#nodePositionForm button'); await saved();
      assert.equal(await page.evaluate(() => S.data.nodes[4].name),'Node 120','absolute order includes hidden nodes');
      await page.evaluate(() => { resetNodes(); failSave=true; nodePositionModal(119); });
      await page.$eval('#nodePosition',el => el.value='1'); await page.click('#nodePositionForm button');
      await page.waitForFunction(() => !S.nodeOrderSaving && $('nodeSortStatus').textContent.includes('test save rejected'));
      assert.equal((await names())[0],'Node 001','failed save restores displayed order');
      await page.evaluate(() => { failSave=false; closeModal(); resetNodes(); });
      await page.$eval('#nodeRows .drag-handle',el => el.focus()); await page.keyboard.press('End'); await saved();
      assert.equal((await names()).at(-1),'Node 001','keyboard End moves to bottom');
    }
    await page.evaluate(() => { resetNodes(); document.querySelector('#nodeRows > .node-card').scrollIntoView({block:'center'}); });
    const firstHandle = await page.$('#nodeRows .drag-handle'), firstBox = await firstHandle.boundingBox();
    await page.mouse.move(firstBox.x+10,firstBox.y+10); await page.mouse.down();
    await page.mouse.move(firstBox.x+10,890,{steps:5});
    await pause(150); const downStart = await page.evaluate(() => scrollY);
    await pause(350); assert(await page.evaluate(() => scrollY)>downStart+100,'stationary edge scroll works downwards');
    const beforeCancel = await page.evaluate(() => sent.length);
    await page.evaluate(() => go('rules')); await page.mouse.up();
    assert.equal(await page.$('.node-drag-ghost'),null,'navigation clears ghost');
    assert.equal(await page.evaluate(() => sent.length),beforeCancel,'navigation cancels without a save');
    await page.evaluate(() => go('nodes'));
    for (const width of [1440,768,390]) {
      await page.setViewport({width,height:900}); await page.evaluate(() => { resetNodes(); scrollTo(0,0); });
      assert(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth),'no horizontal overflow');
      await page.$eval('.node-select',el => el.click());
      assert.equal(await page.$$eval('.node-card.selected',els => els.length),1);
      if (process.env.MXIOC_UI_SCREENSHOT_DIR) {
        await page.$eval('#nodeRows',el => window.scrollTo(0,scrollY+el.getBoundingClientRect().top-220));
        fs.mkdirSync(process.env.MXIOC_UI_SCREENSHOT_DIR,{recursive:true});
        await page.screenshot({path:path.join(process.env.MXIOC_UI_SCREENSHOT_DIR,`node-cards-${width}.png`)});
      }
    }
    // Mobile touch uses the same captured pointer path; ordinary page scrolling is unrestricted outside handles.
    const cdp = await page.createCDPSession();
    await page.evaluate(() => { resetNodes(); document.querySelector('#nodeRows > .node-card').scrollIntoView({block:'center'}); });
    const points = await page.$$eval('#nodeRows > .node-card',cards => cards.slice(0,2).map(card => {const r=card.querySelector('.drag-handle').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};}));
    await cdp.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[points[0]]});
    await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:points[0].x-10,y:points[0].y+10}]});
    await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[points[1]]});
    await pause(80); await cdp.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]}); await saved();
    assert.equal((await names())[0],'Node 002','touch drag reorders');
    await page.evaluate(() => {
      S.data.groups = [{name:'Proxy',config:{proxies:['Node 002']}},{name:'Cloudflare',config:{proxies:['Proxy']}}];
      return nodeGroupsModal(0);
    });
    assert.equal(await page.$$eval('.node-group-picker input:checked',els => els.map(el=>el.value).join(',')),'Proxy');
    await page.$eval('.node-group-picker input[value="Proxy"]',el=>el.click());
    await page.$eval('.node-group-picker input[value="Cloudflare"]',el=>el.click());
    await page.type('#groupSearch','Cloud');
    assert(await page.$eval('[data-group-name="Proxy"]',el=>el.hidden));
    await page.click('#nodeGroupsForm button');
    await page.waitForSelector('#modal.hidden');
    assert.deepEqual(await page.evaluate(()=>membership),{name:'Node 002',groups:['Cloudflare']});
    await page.evaluate(()=>importNodeModal());
    assert((await page.$eval('#nodeLink',el=>el.placeholder)).includes('snell://'));
    await page.evaluate(()=>closeModal());
    assert.deepEqual(errors,[]);
    console.log('PASS: 120-node continuous grid; stationary edge scroll, single-save drag, cancellation, absolute/filtered positions, failed save recovery, keyboard, mobile touch and three themes');
  } finally { await browser.close(); await new Promise(resolve => fixture.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode=1; });
