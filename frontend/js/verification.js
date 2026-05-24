const API_URL = "http://localhost:8000/api/auth";

const verifyOtpForm = document.getElementById("verifyOtpForm");
const otpInputs = document.querySelectorAll(".otp-container input");
const resendOtpLink = document.getElementById("resendOtpLink");

otpInputs.forEach((input, index) => {
    input.addEventListener("input", () => {
        input.value = input.value.replace(/\D/g, "");

        if (input.value && index < otpInputs.length - 1) {
            otpInputs[index + 1].focus();
        }
    });

    input.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !input.value && index > 0) {
            otpInputs[index - 1].focus();
        }
    });
});

verifyOtpForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = localStorage.getItem("pendingEmail");
    const otp = Array.from(otpInputs).map(input => input.value).join("");

    if (!email) {
        alert("No email found. Please register again.");
        window.location.href = "register.html";
        return;
    }

    if (otp.length !== 6) {
        alert("Please enter the 6-digit OTP.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/verify-otp`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email,
                otp
            })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.message);
            return;
        }

        localStorage.removeItem("pendingEmail");

        alert(data.message);
        window.location.href = "login.html";

    } catch (error) {
        console.log(error);
        alert("OTP verification failed.");
    }
});

resendOtpLink.addEventListener("click", async (e) => {
    e.preventDefault();

    const email = localStorage.getItem("pendingEmail");

    if (!email) {
        alert("No email found. Please register again.");
        window.location.href = "register.html";
        return;
    }

    try {
        const response = await fetch(`${API_URL}/resend-otp`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email
            })
        });

        const data = await response.json();
        alert(data.message);

    } catch (error) {
        console.log(error);
        alert("Failed to resend OTP.");
    }
});