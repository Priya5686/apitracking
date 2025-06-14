async function logout() {
    const csrfToken = getCSRFToken();
    const accessToken = await getAccessToken();

    try {
        const res = await fetch("/api/logout/", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${accessToken}`,
                "X-CSRFToken": csrfToken
            },
            credentials: "include"
        });

        if (res.ok) {
            window.location.href = "/";
        } else {
            console.error("❌ Logout failed:", res.status);
        }
    } catch (err) {
        console.error("❌ Error during logout:", err);
    }
}
