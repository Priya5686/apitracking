

//let cachedAccessToken = null;

async function initializeDashboard() {
    cachedAccessToken = await getAccessToken();
    if (!cachedAccessToken) {
        console.warn("No access token found. Redirecting to login.");
        window.location.href = "/login/";
        return;
    }

    await Promise.all([
        loadDashboard(),
        loadAIEvents()
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
            //return data.access_token;
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

async function fetchWithAutoRefresh(url, options = {}) {
    let res = await fetch(url, {
        ...options,
        credentials: "include",
        headers: {
            ...(options.headers || {}),
            Authorization: `Bearer ${cachedAccessToken}`,
        },
    });

    if (res.status === 401) {
        const newToken = await refreshAccessToken();
        if (newToken) {
            // Retry the original request with new access token
            return await fetch(url, {
                ...options,
                credentials: "include",
                headers: {
                    ...(options.headers || {}),
                    Authorization: `Bearer ${newToken}`,
                },
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

    if (!cachedAccessToken) {
        console.warn("No access token found. Redirecting to login.");
        window.location.href = "/login/";
        return;
    }

    try {
        const res = await fetchWithAutoRefresh("/api/whoami/", {
            method: "GET",
            headers: {
                "Authorization": `Bearer ${cachedAccessToken}`
            },
            credentials: "include",
        });

        if (!res.ok) {
            if (res.status === 401 || res.status === 403) {
                console.warn("Unauthorized or expired token. Redirecting to login.");
                window.location.href = "/login/";
                return;
            }
            throw new Error("Failed to load user info");
        }


        const data = await res.json();
        usernameElement.textContent = data.username || "User";
        jsonOutputElement.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        console.error("Error loading dashboard:", err);
        usernameElement.textContent = "Unknown User";
        jsonOutputElement.textContent = "❌ Failed to load user info.";
    }
}
   

    /*if (!accessToken) {
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
        });

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
}*/

async function loadAIEvents() {
    const eventsContainer = document.getElementById("ai-events-output");

    if (!accessToken || !eventsContainer) return;

    try {
        const res = await fetchWithAutoRefresh("/api/gmail-events/", {
           method: "GET",
           headers: {
               "Authorization": `Bearer ${accessToken}`
            },
            credentials: "include"
        });

        if (!res.ok) {
            eventsContainer.innerHTML = `<p>Could not load AI events</p>`;
            return;
        }

        //const events = await res.json();
        const responseData = await res.json();
        const events = responseData.events || [];
        if (!Array.isArray(events) || events.length === 0) {
            eventsContainer.innerHTML = `<p>No upcoming events detected in recent emails.</p>`;
            return;
        }

        events.forEach(event => {
            console.log("👀 Event from backend:", event);

            const block = document.createElement("pre");
            block.classList.add("ai-email-event");

            const type = event.type || "Event";
            const description = event.description || "No description";
            //const notes = event.notes || "—";

            const start = event.start
                ? new Date(event.start).toLocaleString(undefined, {
                    timeZoneName: 'short',
                    hour12: true
                })
                : 'TBD';

            const end = event.end
                ? new Date(event.end).toLocaleString(undefined, {
                    timeZoneName: 'short',
                    hour12: true
                })
                : "TBD";

            // JSON-style output (safe for now)
            block.textContent = JSON.stringify({
                type,
                description,
                start,
                end,
            }, null, 2); // pretty-print

            eventsContainer.appendChild(block);
        });

    } catch (err) {
        console.error("Failed to fetch AI events:", err);
        eventsContainer.innerHTML = `<p>Error loading AI events.</p>`;
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
    loadAIEvents(); 
    handleFlightSearch();
});


function formatTime(isoString) {
    if (!isoString) return null;
    return new Date(isoString).toLocaleString(undefined, {
        timeZoneName: 'short',
        hour12: true
    });
}


document.addEventListener("DOMContentLoaded", async () => {
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
}


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



