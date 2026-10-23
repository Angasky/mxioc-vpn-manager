// Isolated browser fixture; no production credentials, billing, or SSH changes.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const fixture=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(r=>fixture.listen(0,'127.0.0.1',r));
 try {
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(`http://127.0.0.1:${fixture.address().port}/`);
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.profile='clash';S.page='traffic';S.profiles=[{id:'clash',name:'测试订阅',url:'/sub/unchanged'}];
   const plans=[{id:'tier-1',name:'档位1',monthlyGiB:50,price:120},{id:'tier-2',name:'档位2',monthlyGiB:100,price:240},{id:'tier-3',name:'档位3',monthlyGiB:150,price:null}];
   S.data={nodes:[],groups:[],rules:[],profile:{name:'测试订阅',traffic:{configured:false,bindings:[],plans}}};
   window.calls=[];window.confirm=()=>true;
   api=async(url,options)=>{
    window.calls.push({url,body:JSON.parse(options.body)});
    if(window.simulateError)throw Error('服务器离线，套餐未套用');
    const body=JSON.parse(options.body);
    if(url==='/traffic/plans'){
     const plan={...body,id:body.id||'plan-custom'};
     const pos=plans.findIndex(p=>p.id===plan.id);if(pos<0)plans.push(plan);else plans[pos]=plan;
     return {traffic:{...S.data.profile.traffic,plans},plan};
    }
    if(url==='/traffic/plans/delete'){
     plans.splice(plans.findIndex(p=>p.id===body.id),1);
     return {traffic:{...S.data.profile.traffic,plans}};
    }
    if(url==='/traffic/bindings/cleanup')return {removed:3,traffic:{...S.data.profile.traffic,bindings:S.data.profile.traffic.bindings.filter(b=>b.status==='active')}};
    const plan=plans.find(p=>p.id===JSON.parse(options.body).planId);
    return {traffic:{configured:true,plans,planId:plan.id,planName:plan.name,price:plan.price,total:plan.monthlyGiB*1024**3,upload:123,download:456,used:579,percent:0,remaining:plan.monthlyGiB*1024**3-579,resetPeriod:'monthly',nextResetAt:1795420800,expire:1824278400,multiplier:1,bindings:[]}};
   };
   traffic();
  });
  assert.equal(await page.$$eval('.profile-card',els=>els.length),3);
  assert((await page.$eval('#content',el=>el.textContent)).includes('价格未设置'));
  await page.click('#trafficPlanApply');
  assert.equal(await page.$eval('#trafficPlanError',el=>el.textContent),'请先选择套餐模板');
  assert.equal(await page.evaluate(()=>window.calls.length),0);
  for(const [id,amount] of [['tier-1',50],['tier-2',100],['tier-3',150]]){
   await page.select('#trafficPlan',id);await page.click('#trafficPlanApply');
   await page.waitForFunction(id=>S.data.profile.traffic.planId===id,{},id);
   assert.equal(await page.$eval('#trafficTotal',el=>Number(el.value)),amount);
   assert.equal(await page.evaluate(()=>S.profiles[0].url),'/sub/unchanged');
   assert.equal(await page.evaluate(()=>S.data.profile.traffic.used),579);
  }
  assert.equal(await page.evaluate(()=>window.calls.length),3);
  assert.deepEqual(await page.evaluate(()=>window.calls[0]),{url:'/traffic/plan',body:{planId:'tier-1'}});
  await page.evaluate(()=>window.simulateError=true);
  await page.select('#trafficPlan','tier-1');await page.click('#trafficPlanApply');
  await page.waitForFunction(()=>$('trafficPlanError').textContent.includes('离线'));
  assert.equal(await page.$eval('#trafficPlanApply',el=>el.disabled),false);
  await page.evaluate(()=>{window.simulateError=false;subscriptionPlanModal();});
  await page.evaluate(()=>{
   $('planName').value='自定义 <测试>'; $('planPrice').value='99';$('planQuota').value='88';
   $('planMonths').value='6';$('planSpeed').value='20';$('planMultiplier').value='2';
  });
  await page.click('#planSave');
  await page.waitForFunction(()=>S.data.profile.traffic.plans.length===4);
  assert((await page.$eval('#content',el=>el.textContent)).includes('自定义 <测试>'));
  assert.equal(await page.$$eval('.profile-card 测试',els=>els.length),0);
  await page.evaluate(()=>subscriptionPlanModal('plan-custom'));
  assert.equal(await page.$eval('#planMonths',el=>el.value),'6');
  assert.equal(await page.$eval('#planSpeed',el=>el.value),'20');
  await page.evaluate(()=>{$('planName').value='编辑成功';$('planPeriod').value='none';});
  await page.click('#planSave');
  await page.waitForFunction(()=>S.data.profile.traffic.plans.some(p=>p.name==='编辑成功'));
  await page.evaluate(()=>deleteSubscriptionPlan('plan-custom'));
  assert.equal(await page.evaluate(()=>S.data.profile.traffic.plans.length),3);
  assert.equal(await page.evaluate(()=>S.data.profile.traffic.used),579);
  await page.evaluate(()=>{
   S.data.profile.traffic.bindings=['active','detached','revoked','missing'].map((status,i)=>({status,name:'node-'+i,serverId:'s',inboundId:i+1,port:20001+i}));traffic();
  });
  assert.equal(await page.$$eval('#trafficForm > .tablewrap tbody tr',els=>els.length),1);
  assert.equal(await page.$eval('#trafficHistory',el=>el.open),false);
  assert.equal(await page.$$eval('#trafficHistory tbody tr',els=>els.length),3);
  assert.equal(await page.$$eval('#trafficHistory button[onclick*="nodeMultiplier"]',els=>els.length),0);
  await page.click('#trafficHistory summary');await page.click('#trafficCleanup');
  await page.waitForFunction(()=>!$('trafficHistory'));
  assert.equal(await page.evaluate(()=>S.data.profile.traffic.used),579);
  for(const theme of ['high','low','pink']){
   await page.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);
   for(const width of [1440,390]){
    await page.setViewport({width,height:1000});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${theme}/${width} overflow`);
   }
  }
  await page.setViewport({width:1440,height:1100});
  await page.screenshot({path:path.resolve(__dirname,'..','work','subscription-plans.png'),fullPage:true});
  assert.deepEqual(errors,[]);
  console.log('PASS: template CRUD/custom fields/escaping, explicit apply, unchanged URL/usage, errors/retry, collapsed history/local cleanup, desktop/mobile layout');
 }finally{await browser.close();await new Promise(r=>fixture.close(r));}
})().catch(e=>{console.error(e);process.exitCode=1;});
