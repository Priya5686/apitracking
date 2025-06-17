self.addEventListener("push", function(event) {
  let data = {};
  try {
    data = event.data.json();  // Tries to parse incoming push payload
  } catch (e) {
    data = { title: "✈️ Flight Update", body: "New info available!" };  // Fallback
  }

  const title = data.title || "✈️ Flight Update";
  const options = {
    body: data.body || "Your tracked flight has new updates.",
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});
