// Browser checks against the actual running ARM64 image, not the Python fixture.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8099');await page.getByRole('button',{name:'Подключить устройство'}).waitFor();
 const state=await page.evaluate(()=>fetch('api/state').then(r=>r.json()));
 assert.equal(state.version,'5.4');assert.equal(state.ui_build,await page.locator('html').getAttribute('data-build'));
 await page.locator('.brand-icon').evaluate(el=>el.decode());
 const box=await page.locator('.brand-icon').boundingBox();assert.equal(box.width,56);assert.equal(box.height,56);
 assert.equal(await page.locator('#jobs').count(),0);
 await page.getByRole('link',{name:'Telegram MTProxy',exact:true}).click();
 await page.getByRole('button',{name:'Добавить клиента',exact:true}).click();
 await page.getByLabel('Имя клиента').fill('Проверка образа');await page.getByRole('button',{name:'Сохранить',exact:true}).click();
 await page.getByRole('heading',{name:'Проверка образа',exact:true}).waitFor();
 await page.getByRole('link',{name:'Клиенты и история',exact:true}).click();await page.getByRole('button',{name:'Проверка образа',exact:true}).click();
 await page.getByText('Клиент: Проверка образа.',{exact:false}).waitFor();
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});
  for(const hash of ['home','servers','telegram','proxy','access','protection','history','diagnostics','settings']){
   await page.goto('http://127.0.0.1:8099/#'+hash);await page.waitForTimeout(200);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,hash+' '+width);
  }
 }
 await page.goto('http://127.0.0.1:8099/#home');await page.screenshot({path:'/tmp/ui-image-mobile.png',fullPage:true});
 assert.deepEqual(errors,[]);await browser.close();console.log('ARM64 image browser: PASS');
})().catch(e=>{console.error(e);process.exit(1)});
