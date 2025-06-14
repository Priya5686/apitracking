export async function refreshAccessToken() {
    const res = await fetch("/api/refresh-token/", {
        method: "GET",
        credentials: "include",
    });

    if (res.ok) {
        const data = await res.json();
        return data.access_token;
    }
    return null;
}

export async function fetchWithAutoRefresh(url, options = {}) {
    const accessToken = await getAccessToken();

    const res = await fetch(url, {
        ...options,
        headers: {
            ...(options.headers || {}),
            Authorization: `Bearer ${accessToken}`,
        },
        credentials: "include",
    });

    if (res.status === 401) {
        const newToken = await refreshAccessToken();
        if (newToken) {
            return fetch(url, {
                ...options,
                headers: {
                    ...(options.headers || {}),
                    Authorization: `Bearer ${newToken}`,
                },
                credentials: "include",
            });
        }
    }

    return res;
}
