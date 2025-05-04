document.getElementById("register-form").onsubmit = async function (e) {
  e.preventDefault();

  const form = e.target;
  const formData = new FormData(form);
  const data = Object.fromEntries(formData.entries());

  try {
    const res = await fetch("/api/register/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCSRFToken(),
      },
      body: JSON.stringify(data), //
    });

    const result = await res.json();
    if (res.ok) {
      alert(result.msg || "Registration successful!"); // Show success message
      form.reset(); // Clear all fields on success
    } else {
      const errors = await res.json();
      displayErrors(errors);
    }
  } catch (error) {
    console.error("Error during registration:", error);
    alert("An unexpected error occurred. Please try again.");
  }
};


function displayErrors(errors) {

  document.querySelectorAll(".error-message").forEach(el => el.remove());


  for (const [field, messages] of Object.entries(errors)) {
    const input = document.querySelector(`[name="${field}"]`);
    if (input) {
      const errorDiv = document.createElement("div");
      errorDiv.className = "error-message";
      errorDiv.style.color = "red";
      errorDiv.innerText = messages.join(", ");
      input.parentNode.insertBefore(errorDiv, input.nextSibling);
    }
  }
}
// Helper function to retrieve CSRF token
function getCSRFToken() {
  return document.querySelector('meta[name="csrf-token"]').getAttribute("content");
}
