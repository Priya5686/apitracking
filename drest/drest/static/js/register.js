document.getElementById("register-form").onsubmit = async function (e) {
  e.preventDefault();

  const form = e.target;
  const formData = new FormData(form);
  const data = Object.fromEntries(formData.entries());

  document.querySelectorAll(".error-message").forEach(el => el.remove());

  // Basic Client-side Validation
  let hasError = false;

  if (!data.username || data.username.length < 3) {
    showFieldError("username", "Username must be at least 3 characters.");
    hasError = true;
  }

  if (!data.email || !validateEmail(data.email)) {
    showFieldError("email", "Please enter a valid email address.");
    hasError = true;
  }

  if (!data.password || data.password.length < 6) {
    showFieldError("password", "Password must be at least 6 characters.");
    hasError = true;
  }

  if (hasError) return;

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
      alert(result.msg || "Registration successful!"); 
      form.reset(); 
    } else {
      displayErrors(result);
    }
  } catch (error) {
    console.error("Registration error:", error);
    alert("❌ Error: " + error.message || "Unexpected error.");
  }
};

function showFieldError(fieldName, message) {
  const input = document.querySelector(`[name="${fieldName}"]`);
  if (input) {
    const errorDiv = document.createElement("div");
    errorDiv.className = "error-message";
    errorDiv.style.color = "red";
    errorDiv.innerText = message;
    input.parentNode.insertBefore(errorDiv, input.nextSibling);
  }
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


function getCSRFToken() {
  return document.querySelector('meta[name="csrf-token"]').getAttribute("content");
}


function displayErrors(result) {
  document.querySelectorAll(".error-message").forEach(el => el.remove());

  for (const [field, messages] of Object.entries(result)) {
    showFieldError(field, Array.isArray(messages) ? messages.join(", ") : messages);
  }
}


