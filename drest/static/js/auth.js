let cachedAccessToken = null;

export async function getAccessToken() {
    if (cachedAccessToken) return cachedAccessToken;

    try {
        const res = await fetch("/api/get-token/", {
            method: "GET",
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            cachedAccessToken = data.access_token;
            return cachedAccessToken;
        } else {
            console.warn("Access token not found or expired.");
            window.location.href = "/login/";
        }
    } catch (err) {
        console.error("Error fetching access token:", err);
        window.location.href = "/login/";
    }

    return null;
}

export async function refreshAccessToken() {
    try {
        const res = await fetch("/api/refresh-token/", {
            method: "GET",
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            cachedAccessToken = data.access_token;  // update cache
            return cachedAccessToken;
        } else {
            const errData = await res.json();
            console.warn("Refresh token failed:", errData);
        }
    } catch (err) {
        console.error("Network error during refresh:", err);
    }
    return null;
}

export async function fetchWithAutoRefresh(url, options = {}) {
    const accessToken = await getAccessToken();
    if (!accessToken) return new Response(null, { status: 401 });

    let res = await fetch(url, {
        ...options,
        headers: {
            ...(options.headers || {}),
            Authorization: `Bearer ${accessToken}`,
        },
        credentials: "include",
    });

    if (res.status === 401) {
        console.log("Access token expired. Trying refresh...");

        const newToken = await refreshAccessToken();
        if (newToken) {
            return await fetch(url, {
                ...options,
                headers: {
                    ...(options.headers || {}),
                    Authorization: `Bearer ${newToken}`,
                },
                credentials: "include",
            });
        } else {
            console.warn("Refresh token failed. Redirecting to login...");
            window.location.href = "/login/";
        }
    }

    return res;
}
export function scheduleTokenRefresh(intervalSeconds = 3300) {
    setTimeout(async () => {
        const token = await refreshAccessToken();
        if (token) {
            console.log("🔄 Access token refreshed.");
            scheduleTokenRefresh(); // schedule again
        } else {
            console.warn("⚠️ Token refresh failed. Redirecting to login.");
            window.location.href = "/login/";
        }
    }, intervalSeconds * 1000);
}

export function clearCachedToken() {
    cachedAccessToken = null;
}
