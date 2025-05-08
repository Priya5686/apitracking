//import { fetchWithAutoRefresh } from './auth.js';

async function refreshAccessToken() {
    try {
        const res = await fetch("/api/refresh-token/", {
            method: "GET",
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            return data.access_token;
        } else {
            const errData = await res.json();
            console.warn("Refresh token failed:", errData);
        }
    } catch (err) {
        console.error("Network error during refresh:", err);
    }
    return null;
}

async function fetchWithAutoRefresh(url, options = {}) {
    const accessToken = await getAccessToken();

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
            // Retry the original request with new access token
            return fetch(url, {
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


async function loadDashboard() {
    const usernameElement = document.getElementById("username");
    const jsonOutputElement = document.getElementById("json-output");
    const accessToken = await getAccessToken();

    if (!accessToken) {
        window.location.href = "/login/";
        return;
    }

    /*try {
        const res = await fetch("/api/whoami/", {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`
            },
            credentials: "include"
        });*/

    try {
        const res = await fetchWithAutoRefresh("/api/whoami/", {
            method: "GET",
            //headers: {
                //"Authorization": `Bearer ${accessToken}`
            //},
            credentials: "include"
        });


        if (res.status === 403 || res.status === 401) {
            window.location.href = "/login/";
            return;
        }
        const data = await res.json();
        usernameElement.textContent = data.username || "User";
        jsonOutputElement.textContent = JSON.stringify(data, null, 2); // ✨ Pretty-print the full JSON
        } catch (err) {
        console.error("Error loading dashboard:", err);
        usernameElement.textContent = "Unknown User";
        jsonOutputElement.textContent = "❌ Failed to load user info.";
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
                "X-CSRFToken": csrfToken
            },
            credentials: "include",
        });

        if (res.ok) {
            //window.location.href = "/home/";
              window.location.href  = "/";
        } else {
            console.error("❌ Logout failed:", res.status);
        }
    } catch (err) {
        console.error("❌ Error during logout:", err);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadDashboard();


    const params = new URLSearchParams(window.location.search);
    const location = params.get("location");
    if (location) {
        document.getElementById("location-input").value = location;
        loadWeather();
    }

    document.getElementById("weather-btn")?.addEventListener("click", loadWeather);
});

async function loadWeather() {
    const weatherInfo = document.getElementById("weather-info");
    const weatherLocation = document.getElementById("weather-location");
    const weatherUrl = document.getElementById("weather-url");
    const locationInput = document.getElementById("location-input");
    const accessToken = await getAccessToken();

    const location = locationInput.value || "Dubai";
    const apiUrl = `/api/weather/?location=${encodeURIComponent(location)}`;

    // Update browser URL (without reload)
    const newUrl = `${window.location.pathname}?location=${encodeURIComponent(location)}`;
    window.history.pushState({ location }, "", newUrl);

    try {
        const res = await fetch(apiUrl, {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${accessToken}`
            },
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            weatherInfo.textContent = `Temp: ${data.temperature}°C | Code: ${data.weatherCode}`;
            weatherLocation.textContent = `Location: ${location}`;
            //weatherUrl.textContent = `Requested URL: ${apiUrl}`;
        } else {
            weatherInfo.textContent = "Unable to load weather.";
            weatherUrl.textContent = `Tried: ${apiUrl}`;
        }
    } catch (err) {
        console.error("Error fetching weather:", err);
        weatherInfo.textContent = "Error loading weather.";
        weatherUrl.textContent = `Tried: ${apiUrl}`;
    }
}
