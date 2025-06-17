let cachedAccessToken = null;

async function getAccessToken() {
    if (cachedAccessToken) return cachedAccessToken;

    try {
        const res = await fetch("/api/get-token/", {
            method: "GET",
            credentials: "include",
            cache: "no-store" 
        });

        if (res.ok) {
            const data = await res.json();
            if (data.access_token) {
                cachedAccessToken = data.access_token;
                console.log("✅ Access token fetched:", cachedAccessToken);
                return cachedAccessToken;
            } else {
                console.warn("⚠️ Access token missing in response.");
            }
        } else {
            const error = await res.json();
            console.warn("❌ Failed to fetch token:", error?.error || res.statusText);
        }
    } catch (err) {
        console.error("❌ Error during token fetch:", err);
    }

    // Redirect if token is not available
    window.location.href = "/login/";
    return null;
}


function getCSRFToken() {
    return document.cookie
        .split("; ")
        .find(row => row.startsWith("csrftoken="))
        ?.split("=")[1] || "";
}
