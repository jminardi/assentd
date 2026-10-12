// assentd service worker: shows Web Push notifications and opens the request on tap.
// It deliberately has no fetch handler, so it never caches the page: updates apply on next load.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = { title: "assentd", body: event.data?.text() || "" }; }
  event.waitUntil(self.registration.showNotification(data.title || "assentd", {
    body: data.body || "",
    tag: data.tag || undefined,
    data: { url: data.url || "/" },
    icon: "/icon-192.png",
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  // Only ever open pages on this origin, whatever the payload says.
  const url = new URL(event.notification.data?.url || "/", self.location.origin);
  const target = url.origin === self.location.origin ? url.href : self.location.origin + "/";
  event.waitUntil((async () => {
    for (const client of await self.clients.matchAll({ type: "window", includeUncontrolled: true })) {
      if ("navigate" in client) {
        await client.focus();
        return client.navigate(target);
      }
    }
    return self.clients.openWindow(target);
  })());
});
