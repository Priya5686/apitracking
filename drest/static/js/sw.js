// sw.js

self.addEventListener("push", function(event) {
    let data = {};
    
    try {
      data = event.data.json();
    } catch (e) {
      console.warn("⚠️ Push event had no JSON data. Using fallback.");
      data = { title: "✈️ Flight Update", body: "There is a new update on your flight." };
    }
  
    const title = data.title || "✈️ Flight Update";
    const options = {
      body: data.body || "Check your dashboard for more details.",
    };
  
    event.waitUntil(
      self.registration.showNotification(title, options)
    );
  });
  
  self.addEventListener("notificationclick", function(event) {
    event.notification.close();
    event.waitUntil(
      clients.matchAll({ type: "window" }).then(clientList => {
        for (const client of clientList) {
          if (client.url === "/" && "focus" in client) {
            return client.focus();
          }
        }
        if (clients.openWindow) {
          return clients.openWindow("/dashboard/"); // or your desired route
        }
      })
    );
  });
  