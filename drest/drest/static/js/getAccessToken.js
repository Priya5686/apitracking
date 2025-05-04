async function getAccessToken() {
    try {
        const res = await fetch("/api/get-token/",
        {
            method: "GET",
            credentials: "include",
        });
        if (res.ok) {
            const data = await res.json();
            return data.access_token;
        }
    } catch (err) {
        console.error("Error fetching access token:", err);
    }
    return null;
}
function getCSRFToken() {
    return document.cookie
        .split("; ")
        .find(row => row.startsWith("csrftoken="))
        ?.split("=")[1] || "";
}