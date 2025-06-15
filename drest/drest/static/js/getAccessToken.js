let cachedAccessToken = null;

async function getAccessToken() {
    if (cachedAccessToken) return cachedAccessToken;
    try {
        const res = await fetch("/api/get-token/",
        {
            method: "GET",
            credentials: "include",
        });
        if (res.ok) {
            const data = await res.json();
            cachedAccessToken = data.access_token;
            //return data.access_token;
            return cachedAccessToken;
        }
    } catch (err) {
        console.error("Error fetching access token:", err);
    }
    return null;
}

window.getAccessToken = getAccessToken;

function getCSRFToken() {
    return document.cookie
        .split("; ")
        .find(row => row.startsWith("csrftoken="))
        ?.split("=")[1] || "";
}