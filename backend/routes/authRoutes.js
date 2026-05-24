const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const axios = require("axios");
const db = require("../config/db");

const verifyAppKey = require("../middleware/appKeyMiddleware");
const verifyToken = require("../middleware/authMiddleware");

const {
    register,
    login,
    refreshAccessToken,
    forgotPassword,
    resetPassword,
    verifyEmail,
    verifyOtp,
    resendOtp
} = require("../controllers/authController");

const {
    loginLimiter,
    otpLimiter,
    forgotPasswordLimiter
} = require("../middleware/rateLimiter");

const {
    registerValidation,
    loginValidation,
    emailValidation,
    otpValidation,
    resetPasswordValidation
} = require("../middleware/validationMiddleware");

const router = express.Router();


// =========================
// AUTH ROUTES
// =========================

router.post("/register", otpLimiter, registerValidation, register);

router.post("/login", loginLimiter, loginValidation, login);

router.post("/refresh-token", refreshAccessToken);

router.post("/forgot-password", forgotPasswordLimiter, emailValidation, forgotPassword);

router.post("/reset-password", resetPasswordValidation, resetPassword);

router.post("/verify-otp", otpLimiter, otpValidation, verifyOtp);

router.post("/resend-otp", otpLimiter, emailValidation, resendOtp);

// Optional email verification link route
router.get(
    "/verify-email/:token",
    verifyEmail
);

router.get("/profile", verifyToken, (req, res) => {
    res.json({
        message: "Protected route accessed",
        user: req.user
    });
});


// =========================
// GOOGLE OAUTH
// =========================

router.get(
    "/google",
    passport.authenticate("google", {
        scope: ["profile", "email"]
    })
);

router.get(
    "/google/callback",
    passport.authenticate("google", {
        session: false,
        failureRedirect: "http://localhost:5500/login.html"
    }),
    (req, res) => {
        const accessToken = jwt.sign(
            {
                id: req.user.id,
                email: req.user.email
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "15m"
            }
        );

        const refreshToken = jwt.sign(
            {
                id: req.user.id
            },
            process.env.REFRESH_SECRET,
            {
                expiresIn: "7d"
            }
        );

        const db = require("../config/db");

        db.query(
            "UPDATE users SET refresh_token = ? WHERE id = ?",
            [refreshToken, req.user.id],
            (err) => {
                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                res.cookie("refreshToken", refreshToken, {
                    httpOnly: true,
                    secure: false,
                    sameSite: "lax",
                    maxAge: 7 * 24 * 60 * 60 * 1000
                });

                res.redirect("http://localhost:5500/frontend/home.html");
            }
        );
    }
);


// =========================
// PROTECTED ROUTES
// =========================

router.get(
    "/profile",
    verifyAppKey,
    verifyToken,
    (req, res) => {
        res.json({
            message: "Protected route accessed",
            user: req.user
        });
    }
);

// =========================
// X OAUTH 2.0 LOGIN
// =========================
router.get("/x", (req, res) => {
    const state = crypto.randomBytes(16).toString("hex");

    const codeVerifier = crypto
        .randomBytes(32)
        .toString("base64url");

    const codeChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");

    req.session.x_oauth_state = state;
    req.session.x_code_verifier = codeVerifier;

    const params = new URLSearchParams({
        response_type: "code",
        client_id: process.env.X_CLIENT_ID,
        redirect_uri: process.env.X_CALLBACK_URL,
        scope: "tweet.read users.read",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256"
    });

    res.redirect(`https://x.com/i/oauth2/authorize?${params.toString()}`);
});


// =========================
// X OAUTH 2.0 CALLBACK
// =========================
router.get("/x/callback", async (req, res) => {
    try {
        const { code, state } = req.query;

        if (!code) {
            return res.status(400).json({
                message: "Authorization code missing"
            });
        }

        if (!state || state !== req.session.x_oauth_state) {
            return res.status(400).json({
                message: "Invalid OAuth state"
            });
        }

        const tokenResponse = await axios.post(
            "https://api.x.com/2/oauth2/token",
            new URLSearchParams({
                code,
                grant_type: "authorization_code",
                client_id: process.env.X_CLIENT_ID,
                redirect_uri: process.env.X_CALLBACK_URL,
                code_verifier: req.session.x_code_verifier
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                auth: {
                    username: process.env.X_CLIENT_ID,
                    password: process.env.X_CLIENT_SECRET
                }
            }
        );

        const xAccessToken = tokenResponse.data.access_token;

        const userResponse = await axios.get(
            "https://api.x.com/2/users/me",
            {
                headers: {
                    Authorization: `Bearer ${xAccessToken}`
                }
            }
        );

        const xUser = userResponse.data.data;

        db.query(
            "SELECT * FROM users WHERE provider = ? AND provider_id = ?",
            ["x", xUser.id],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                if (result.length > 0) {
                    const user = result[0];

                    return finishXLogin(res, user);
                }

                db.query(
                    `INSERT INTO users
                    (username, email, password, is_verified, provider, provider_id)
                    VALUES (?, ?, NULL, 1, ?, ?)`,
                    [
                        xUser.username,
                        null,
                        "x",
                        xUser.id
                    ],
                    (err, insertResult) => {
                        if (err) {
                            return res.status(500).json({
                                message: err.message
                            });
                        }

                        const newUser = {
                            id: insertResult.insertId,
                            username: xUser.username,
                            email: null,
                            is_verified: 1,
                            provider: "x"
                        };

                        return finishXLogin(res, newUser);
                    }
                );
            }
        );

    } catch (error) {
        console.log(error.response?.data || error.message);

        res.status(500).json({
            message: "X OAuth failed",
            error: error.response?.data || error.message
        });
    }
});


// =========================
// FINISH X LOGIN
// =========================
function finishXLogin(res, user) {
    const refreshToken = jwt.sign(
        {
            id: user.id
        },
        process.env.REFRESH_SECRET,
        {
            expiresIn: "7d"
        }
    );

    db.query(
        "UPDATE users SET refresh_token = ? WHERE id = ?",
        [refreshToken, user.id],
        (err) => {
            if (err) {
                return res.status(500).json({
                    message: err.message
                });
            }

            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: "lax",
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            return res.redirect("http://localhost:5500/frontend/home.html");
        }
    );
}

module.exports = router;