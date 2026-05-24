const API_URL = "http://localhost:8000/api/auth";

async function refreshAccessToken() {
    const response = await fetch(`${API_URL}/refresh-token`, {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "application/json"
        }
    });

    const data = await response.json();

    if (!response.ok) {
        console.log("Refresh error:", data);
        throw new Error(data.message);
    }

    localStorage.setItem("accessToken", data.accessToken);
    return data.accessToken;
}

async function loadProfile() {
    let accessToken = localStorage.getItem("accessToken");

    if (!accessToken) {
        try {
            accessToken = await refreshAccessToken();
        } catch (error) {
            console.log("No valid refresh token:", error.message);
            window.location.href = "login.html";
            return;
        }
    }

    let response = await fetch(`${API_URL}/profile`, {
        method: "GET",
        credentials: "include",
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    if (response.status === 401 || response.status === 403) {
        try {
            accessToken = await refreshAccessToken();

            response = await fetch(`${API_URL}/profile`, {
                method: "GET",
                credentials: "include",
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            });

        } catch (error) {
            console.log("Refresh failed:", error.message);
            localStorage.removeItem("accessToken");
            window.location.href = "login.html";
            return;
        }
    }

    const data = await response.json();

    if (!response.ok) {
        console.log("Profile error:", data);
        localStorage.removeItem("accessToken");
        window.location.href = "login.html";
        return;
    }

    console.log("Logged in user:", data.user);
}

loadProfile();