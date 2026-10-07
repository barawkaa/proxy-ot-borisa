"""Ingress-shaped proxy with the HA static CacheFirst/ignoreSearch behavior.

Uses immutable v5.0/v5.1 assets from git. This is a focused compatibility
fixture, not a claim that the complete Home Assistant OS runs in this test.
"""
import os
import subprocess
from pathlib import Path
import aiohttp
from aiohttp import web

ROOT=Path(__file__).resolve().parents[2]
PREFIX='/api/hassio_ingress/test/'
UPSTREAM=os.environ.get('UPGRADE_UPSTREAM','http://127.0.0.1:18099')
version='5.0'
old={}
for tag in ('5.0','5.1'):
    for name in ('index.html','style.css','app.js','logo.png'):
        if tag=='5.0' and name=='logo.png':continue
        old[tag,name]=subprocess.check_output(['git','show',f'v{tag}:proxy-ot-borisa/ui/{name}'],cwd=ROOT)

SW="""
self.addEventListener('install',e=>{self.skipWaiting()});
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
 const url=new URL(e.request.url);
 // Same ordering and matching policy as HA's service worker static route.
 if(/\\/(static|frontend_latest|frontend_es5)\\/.+/.test(url.pathname)){
  e.respondWith((async()=>{
   const cache=await caches.open('ha-static-test');
   const hit=await cache.match(e.request,{ignoreSearch:true});
   if(hit)return hit;
   const response=await fetch(e.request);
   if(response.ok)await cache.put(e.request,response.clone());
   return response;
  })());
 }
});
"""

async def shell(request):
    return web.Response(text='<html><body style="margin:0"><iframe title="Addon" src="'+PREFIX+'" style="border:0;width:100%;height:100vh"></iframe></body></html>',content_type='text/html')

async def worker(request):return web.Response(text=SW,content_type='text/javascript')

async def change(request):
    global version
    selected=(await request.json())['version']
    if selected not in ('5.0','5.1','current'):raise web.HTTPBadRequest()
    version=selected
    return web.json_response({'version':version})

async def ingress(request):
    path=request.match_info['path']
    if version!='current' and (not path or path.startswith('static/')):
        name=path.removeprefix('static/') or 'index.html'
        body=old.get((version,name))
        if body is None:raise web.HTTPNotFound()
        mime={'html':'text/html','css':'text/css','js':'text/javascript','png':'image/png'}[name.rsplit('.',1)[1]]
        return web.Response(body=body,content_type=mime,headers={'Cache-Control':'no-store'})
    headers={key:request.headers[key] for key in ('Content-Type','X-Boris-Request') if key in request.headers}
    async with aiohttp.ClientSession() as client:
        async with client.request(request.method,UPSTREAM+'/'+path+('?' + request.query_string if request.query_string else ''),data=await request.read(),headers=headers) as response:
            return web.Response(body=await response.read(),status=response.status,headers={k:v for k,v in response.headers.items() if k.lower() in ('content-type','cache-control','content-security-policy','x-content-type-options')})

app=web.Application()
app.router.add_get('/',shell)
app.router.add_get('/sw.js',worker)
app.router.add_post('/test/version',change)
app.router.add_route('*',PREFIX+'{path:.*}',ingress)
web.run_app(app,host='127.0.0.1',port=18100,access_log=None)
