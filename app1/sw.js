/* Same-origin service worker. The previous file was a third-party push
   worker (importScripts from 5gvci.com) which failed on localhost, requested
   notification permission, and filled the console after login. */
self.addEventListener("install", function (event) {
  self.skipWaiting();
});
self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());
});
