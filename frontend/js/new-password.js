const API_URL = "http://localhost:8000/api/auth";

const newPasswordForm = document.getElementById("newPasswordForm");

newPasswordForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");

    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    if (!token) {
        alert("Reset token missing.");
        window.location.href = "forgot-password.html";
        return;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/reset-password`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                token,
                password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.message);
            return;
        }

        alert(data.message);
        window.location.href = "login.html";

    } catch (error) {
        console.log(error);
        alert("Password reset failed.");
    }
});