import { fetchWithAutoRefresh } from './auth.js';

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
            headers: {
                "Authorization": `Bearer ${accessToken}`
            },
            credentials: "include"
        });*/


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
