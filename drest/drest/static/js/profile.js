async function loadProfile() {
    const firstNameInput = document.getElementById("first_name");
    const lastNameInput = document.getElementById("last_name");
    const statusMessage = document.getElementById("status-message");

    const accessToken = await getAccessToken();

    if (!accessToken) {
        statusMessage.textContent = "❌ Not authenticated.";
        return;
    }

    try {
        const res = await fetch("/api/account/", {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
            },
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            firstNameInput.value = data.first_name || "";
            lastNameInput.value = data.last_name || "";
        } else {
            statusMessage.textContent = "❌ Failed to load profile.";
        }
    } catch (err) {
        console.error("Error loading profile:", err);
        statusMessage.textContent = "❌ Error loading profile.";
    }
}

async function updateProfile() {
    const firstName = document.getElementById("first_name").value.trim();
    const lastName = document.getElementById("last_name").value.trim();
    const statusMessage = document.getElementById("status-message");

    if (!firstName || !lastName) {
        statusMessage.textContent = "❌ Both fields required.";
        return;
    }

    const csrfToken = getCSRFToken();
    const accessToken = await getAccessToken();

    try {
        const res = await fetch("/api/account/", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${accessToken}`,
                "X-CSRFToken": csrfToken,
            },
            body: JSON.stringify({ first_name: firstName, last_name: lastName }),
        });

        const result = await res.json();
        console.log("Update result:", result);

        if (res.ok) {
            statusMessage.textContent = "Profile updated!";
            document.getElementById("first_name").value = "";
            document.getElementById("last_name").value = "";

            setTimeout(() => {
                statusMessage.textContent = "";
            }, 3000);
            //loadProfile();
        } else {
            statusMessage.textContent = `❌ ${result.msg || "Update failed."}`;
        }
    } catch (err) {
        console.error("Error updating profile:", err);
        statusMessage.textContent = "❌ Error updating profile.";
    }
}


async function logout() {
    const csrfToken = getCSRFToken();
    const accessToken = await getAccessToken();

    try {
        const res = await fetch("/api/logout/", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "X-CSRFToken": csrfToken,
            },
            credentials: "include",
        });

        if (res.ok) {
            window.location.href = "/";  // Redirect to home page
        } else {
            console.error("❌ Logout failed:", res.status);
        }
    } catch (err) {
        console.error("❌ Error during logout:", err);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadProfile();
    document.getElementById("update-btn").addEventListener("click", updateProfile);


    const logoutLink = document.querySelector('a[onclick="logout()"]');
    if (logoutLink) {
        logoutLink.addEventListener("click", (e) => {
            e.preventDefault();
            logout();
        });
    }
});

function getCSRFToken() {
    return document.cookie
        .split("; ")
        .find(row => row.startsWith("csrftoken="))
        ?.split("=")[1] || "";
}



