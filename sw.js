const CACHE = 'finbench-v18';
const SHELL = ['./', './index.html', './manifest.json', './icon.svg'];
self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(() => {})));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  // cross-origin (public quote APIs): never intercept, let browser hit network directly
  if (url.origin !== location.origin) return;
  // HTML/navigations: network-first so updates are picked up immediately, cache fallback offline
  const isDoc = e.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html');
  if (isDoc) {
    e.respondWith(
      fetch(e.request).then(res => {
        const cp = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, cp)).catch(() => {});
        return res;
      }).catch(() => caches.match(e.request).then(r => r || caches.match('./index.html')))
    );
    return;
  }
  // same-origin assets: cache-first
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request).then(res => {
      const cp = res.clone();
      caches.open(CACHE).then(c => c.put(e.request, cp)).catch(() => {});
      return res;
    }))
  );
});
