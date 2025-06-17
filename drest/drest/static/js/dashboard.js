async function initializeDashboard() {
    const accessToken = await getAccessToken();
    if (!accessToken) return;

    await Promise.all([
        loadDashboard(accessToken),
        loadAIEvents(accessToken)
    ]);
}

window.addEventListener("DOMContentLoaded", initializeDashboard);

async function refreshAccessToken() {
    try {
        const res = await fetch("/api/refresh-token/", {
            method: "GET",
            credentials: "include",
        });

        if (res.ok) {
            const data = await res.json();
            cachedAccessToken = data.access_token;
            console.log("🔁 Access token refreshed:", cachedAccessToken);
            return cachedAccessToken;
        } else {
            console.warn("⚠️ Refresh token request failed.");
        }
    } catch (err) {
        console.error("❌ Error during token refresh:", err);
    }
    return null;
}

async function fetchWithAutoRefresh(url, options = {}) {
    let token = await getAccessToken();
    let res = await fetch(url, {
        ...options,
        credentials: "include",
        headers: {
            ...(options.headers || {}),
            Authorization: `Bearer ${token}`,
        },
    });

    if (res.status === 401) {
        console.warn("⏳ Token expired. Refreshing...");
        const newToken = await refreshAccessToken();
        if (newToken) {
            res = await fetch(url, {
                ...options,
                credentials: "include",
                headers: {
                    ...(options.headers || {}),
                    Authorization: `Bearer ${newToken}`,
                },
            });
        } else {
            window.location.href = "/login/";
        }
    }

    return res;
}

async function loadDashboard(token) {
    const usernameTop = document.getElementById("navbar-username");
    const usernameMain = document.getElementById("main-username");
    const jsonOutput = document.getElementById("json-output");

    try {
        const res = await fetchWithAutoRefresh("/api/whoami/", {
            method: "GET",
            credentials: "include",
            cache: "no-store",
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        if (!res.ok) throw new Error("Failed to load user info.");

        const data = await res.json();
        usernameTop.textContent = data.username || "User";
        usernameMain.textContent = data.username || "User";
        jsonOutput.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        console.error("❌ loadDashboard error:", err);
        usernameTop.textContent = "Unknown";
        usernameMain.textContent = "Unknown";
        jsonOutput.textContent = "❌ Failed to load user info.";
    }
}

async function loadAIEvents(token) {
    const container = document.getElementById("ai-events-output");
    container.innerHTML = "Loading...";

    try {
        const res = await fetchWithAutoRefresh("/api/gmail-events/", {
            method: "GET",
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        const data = await res.json();
        const events = data.events || [];

        if (!events.length) {
            container.innerHTML = "<p>No AI-detected events found.</p>";
            return;
        }

        container.innerHTML = "";
        events.forEach(event => {
            const pre = document.createElement("pre");
            pre.textContent = JSON.stringify(event, null, 2);
            container.appendChild(pre);
        });
    } catch (err) {
        console.error("❌ loadAIEvents error:", err);
        container.innerHTML = "<p>Error loading AI events.</p>";
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
            window.location.href = "/";
        } else {
            console.error("❌ Logout failed:", res.status);
        }
    } catch (err) {
        console.error("❌ Error during logout:", err);
    }

function formatTime(isoString) {
    if (!isoString) return null;
    return new Date(isoString).toLocaleString(undefined, {
        timeZoneName: 'short',
        hour12: true
    });
}


/*document.addEventListener("DOMContentLoaded", async () => {
    await loadFallbackEvents();
});

async function loadFallbackEvents() {
    const eventsContainer = document.getElementById("fallback-events-output");

    try {
        const params = new URLSearchParams({ text: "Fetch fallback events" });

        const res = await fetch(`/api/extract-events-fallback/?${params.toString()}`, {
            method: "GET",
            headers: { "Content-Type": "application/json" },
            credentials: "include"
        });

        if (!res.ok) {
            eventsContainer.innerHTML = `<p>❌ Failed to load fallback events.</p>`;
            return;
        }

        const responseData = await res.json();
        console.log("🔍 Extracted Event Response:", responseData);

        const events = responseData.events || [];
        if (!Array.isArray(events) || events.length === 0) {
            eventsContainer.innerHTML = `<p>No fallback events detected.</p>`;
            return;
        }

        eventsContainer.innerHTML = "";
        events.forEach(event => {
            const block = document.createElement("pre");
            block.classList.add("fallback-event");
            block.textContent = JSON.stringify(event, null, 2);
            eventsContainer.appendChild(block);
        });

    } catch (err) {
        console.error("❌ Error loading fallback events:", err);
        eventsContainer.innerHTML = `<p>Error retrieving fallback events.</p>`;
    }
}*/


async function handleFlightSearch() {
    const flightNumber = document.getElementById("flight_number").value;
    const flightDate = document.getElementById("flight_date").value;
    const airlineName = document.getElementById("airline_name").value;

    if (!flightNumber || !flightDate || !airlineName) {
        displayMessage("❌ Please fill in all fields.");
        return;
    }

    const params = new URLSearchParams({
        flight_number: flightNumber,
        scheduled: flightDate,
        airline_name: airlineName
    });

    const requestUrl = `/api/fetch-flight-data/?${params.toString()}`;
    console.log("📡 Fetching from:", requestUrl);

    try {
        const res = await fetch(requestUrl, {
            method: "GET",
            credentials: "include",
        });

        const flightData = await res.json();
        console.log("✈️ Response:", flightData);

        if (flightData.error) {
            displayMessage(`❌ ${flightData.error}`);
        } else {
            updateFlightUI(flightData);
        }

    } catch (error) {
        console.error("❌ Error fetching data:", error);
        displayMessage("❌ Could not retrieve flight data.");
    }
}

function updateFlightUI(flightData) {
    const container = document.getElementById("flight-data-output");
    container.innerHTML = "";

    const div = document.createElement("div");
    div.className = "flight-info";

    div.innerHTML = `
    <h3>${flightData.airline_name} ${flightData.flight_number}</h3>
    <p><strong>Departure:</strong> ${flightData.scheduled_departure_airport} (${flightData.scheduled_departure_code})</p>
    <p><strong>Arrival:</strong> ${flightData.scheduled_arrival_airport} (${flightData.scheduled_arrival_code})</p>
    <p><strong>Scheduled Departure:</strong> ${flightData.scheduled_departure_time}</p>
    <p><strong>Actual Departure:</strong> ${flightData.actual_departure_time || "N/A"}</p>
    <p><strong>Gate (Departure):</strong> ${flightData.gate_number_departure || "TBA"}</p>
    <p><strong>Gate (Arrival):</strong> ${flightData.arrival_gate || "TBA"}</p>
    <p><strong>Arrival Belt:</strong> ${flightData.arrival_belt_number || "N/A"}</p>
    <p><strong>Baggage Check-in Start:</strong> ${flightData.baggage_checkin_starttime || "Unknown"}</p>
    <p><strong>Baggage Check-in End:</strong> ${flightData.baggage_checkin_endtime || "Unknown"}</p>
    <p><strong>Scheduled Boarding Start:</strong> ${flightData.scheduled_boarding_time_start || "Unknown"}</p>
    <p><strong>Scheduled Boarding End:</strong> ${flightData.scheduled_boarding_time_end || "Unknown"}</p>
    <p><strong>Boarding Pass Info:</strong> ${flightData.boarding_pass_info || "Unavailable"}</p>
    <p><strong>Check-in Tag Number:</strong> ${flightData.checkin_tag_number || "Not Assigned"}</p>
    <p><strong>Scheduked Arrival Time:</strong> ${flightData.scheduled_arrival_time}</p>
`;

    container.appendChild(div);
}

function displayMessage(message) {
    const container = document.getElementById("flight-data-output");
    container.innerHTML = `<p>${message}</p>`;
}



