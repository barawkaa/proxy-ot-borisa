const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const setVersion=async version=>{const r=await context.request.post('http://127.0.0.1:18100/test/version',{data:{version}});assert(r.ok())};
 await setVersion('5.0');await page.goto('http://127.0.0.1:18100');
 await page.evaluate(async()=>{await navigator.serviceWorker.register('/sw.js');await navigator.serviceWorker.ready});
 await page.reload();await page.waitForFunction(()=>!!navigator.serviceWorker.controller);
 let frame=page.frameLocator('iframe');await frame.locator('#nav a').first().waitFor();
 await page.waitForFunction(async()=>{const c=await caches.open('ha-static-test');return !!await c.match('/api/hassio_ingress/test/static/style.css')&&!!await c.match('/api/hassio_ingress/test/static/app.js')});
 await setVersion('5.1');await page.reload();
 await frame.locator('img.brand-icon').waitFor();
 await frame.locator('img.brand-icon').evaluate(el=>el.decode());
 assert((await frame.locator('.brand-icon').boundingBox()).width>500,'Must reproduce the reported 5.1 logo regression first');
 const queryCss=await page.evaluate(()=>fetch('/api/hassio_ingress/test/static/style.css?v=5.1').then(r=>r.text()));
 assert(!queryCss.includes('width:56px'),'HA cache policy ignores query version');
 await page.screenshot({path:'/tmp/ui-upgrade-reproduced-5.1.png',fullPage:true});
 // No cache deletion, no unregister, no new browser context.
 await setVersion('5.2');await page.reload();
 await frame.getByRole('heading',{name:'Выбор сервера'}).waitFor();
 assert.equal((await frame.locator('.brand-icon').boundingBox()).width,56);
 await setVersion('current');await page.reload();
 await frame.getByRole('button',{name:'Подключить устройство'}).waitFor();
 for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  await page.setViewportSize(viewport);
  const box=await frame.locator('.brand-icon').boundingBox();assert.equal(box.width,56);assert.equal(box.height,56);
  assert.equal(await frame.locator('#jobs').count(),0);
 }
 await page.setViewportSize({width:1440,height:1000});
 await frame.getByRole('link',{name:'Клиенты и история',exact:true}).click();
 await frame.getByRole('button',{name:'Борис',exact:true}).click();
 await frame.getByRole('cell',{name:'Борис',exact:true}).first().waitFor();
 await page.waitForFunction(()=>!document.querySelector('iframe').contentDocument.querySelector('#content').textContent.includes('example-guest'));
 assert.equal(await frame.getByRole('cell',{name:'Гость',exact:true}).count(),0);
 await frame.getByRole('button',{name:'Все клиенты',exact:true}).click();
 await frame.getByRole('cell',{name:'Гость',exact:true}).first().waitFor();
 await frame.getByRole('button',{name:'Борис',exact:true}).click();
 await frame.getByRole('link',{name:'Диагностика',exact:true}).click();
 await frame.locator('.connection').filter({hasText:'Событие для проверки диагностики'}).waitFor();
 await frame.getByRole('link',{name:'Главная',exact:true}).click();
 await frame.getByRole('button',{name:'Подключить устройство'}).waitFor();
 await page.screenshot({path:'/tmp/ui-upgrade-5.4.png',fullPage:true});
 // Even a failed stylesheet cannot enlarge the image.
 await context.route('**/assets/**/style.css',route=>route.abort());
 await page.reload();await frame.locator('img.brand-icon').waitFor();
 const fallback=await frame.locator('.brand-icon').boundingBox();assert.equal(fallback.width,56);assert.equal(fallback.height,56);
 assert.deepEqual(errors,[]);await browser.close();console.log('Upgrade 5.0 → broken 5.1 → 5.4, cached assets, client filters and CSS failure: PASS');
})().catch(e=>{console.error(e);process.exit(1)});
