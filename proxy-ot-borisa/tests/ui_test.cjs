const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:18099');await page.getByRole('heading',{name:'Выбор сервера'}).waitFor();
 assert.equal(await page.locator('#jobs .job').count(),0);
 assert(await page.locator('.brand-icon').evaluate(el=>el.complete&&el.naturalWidth>0));
 await page.getByText('Задержка HTTPS',{exact:true}).waitFor();await page.screenshot({path:'/tmp/ui-home.png',fullPage:true});
 await page.getByRole('link',{name:'Telegram MTProxy',exact:true}).click();
 await page.getByRole('button',{name:'Добавить клиента',exact:true}).click();await page.getByLabel('Имя клиента').fill('Тестовый клиент');
 await page.getByRole('button',{name:'Сохранить',exact:true}).click();await page.getByRole('heading',{name:'Тестовый клиент',exact:true}).waitFor();
 await page.getByRole('link',{name:'Клиенты и история',exact:true}).click();
 await page.getByRole('cell',{name:'Борис',exact:true}).waitFor();await page.getByRole('cell',{name:'Гость',exact:true}).waitFor();
 await page.getByRole('button',{name:'Борис',exact:true}).click();
 await page.waitForFunction(()=>!document.querySelector('#content table')?.textContent.includes('Гость'));
 assert.equal(await page.getByRole('cell',{name:'Гость',exact:true}).count(),0);
 await page.screenshot({path:'/tmp/ui-history.png',fullPage:true});
 await page.getByRole('button',{name:'Все клиенты',exact:true}).click();await page.getByRole('cell',{name:'Гость',exact:true}).waitFor();
 await page.getByRole('link',{name:'Серверы',exact:true}).click();await page.getByRole('button',{name:'Основная подписка',exact:true}).click();
 await page.getByText('🇳🇱 Нидерланды ⭐',{exact:true}).waitFor();await page.screenshot({path:'/tmp/ui-servers.png',fullPage:true});
 await page.getByRole('link',{name:'Настройки',exact:true}).click();
 assert.equal(await page.getByText('Скачать настройки',{exact:true}).count(),0);
 await page.locator('[data-action="security"]').click();await page.getByLabel('Разрешить доверенным адресам доступ без пароля').check();
 await page.getByRole('button',{name:'Добавить доверенный адрес',exact:true}).click();await page.locator('.trusted-cidr').fill('192.168.1.20/32');
 await page.getByRole('button',{name:'Сохранить',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('dialog').open);
 const security=await page.evaluate(async()=>{const r=await fetch('api/state');return (await r.json()).config.security});assert.equal(security.trusted.length,1);assert.deepEqual(security.trusted[0].protocols,['http']);
 for(const hash of ['home','servers','telegram','proxy','history','diagnostics','settings']){
   await page.goto('http://127.0.0.1:18099/#'+hash);await page.waitForTimeout(150);
 }
 await page.setViewportSize({width:390,height:844});
 for(const hash of ['home','servers','telegram','history','settings']){
   await page.goto('http://127.0.0.1:18099/#'+hash);await page.waitForTimeout(200);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'Overflow: '+hash);
   if(hash==='home')await page.screenshot({path:'/tmp/ui-mobile.png',fullPage:true});
 }
 console.log(JSON.stringify({errors}));await browser.close();assert.deepEqual(errors,[]);
})().catch(e=>{console.error(e);process.exit(1)});
