const CACHE='sjdona-static-v2';
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{const keys=await caches.keys();await Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)));await self.clients.claim();})()));
self.addEventListener('fetch',event=>{const req=event.request;if(req.method!=='GET')return;const url=new URL(req.url);if(url.origin!==self.location.origin)return;if(req.mode==='navigate'||url.pathname==='/'||url.pathname==='/index.html'||url.pathname.startsWith('/api/')){event.respondWith(fetch(req,{cache:'no-store'}));return;}event.respondWith(fetch(req).catch(()=>caches.match(req)));});
