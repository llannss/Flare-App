const db = require("../config/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

// REGISTER
const register = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const otpCode = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const otpExpiry = new Date(Date.now() + 1000 * 60 * 10);

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                if (result.length > 0) {
                    return res.status(400).json({
                        message: "Email already exists"
                    });
                }

                db.query(
                    `INSERT INTO users 
                    (username, email, password, otp_code, otp_expiry, is_verified) 
                    VALUES (?, ?, ?, ?, ?, 0)`,
                    [
                        username,
                        email,
                        hashedPassword,
                        otpCode,
                        otpExpiry
                    ],
                    async (err) => {
                        if (err) {
                            return res.status(500).json({
                                message: err.message
                            });
                        }

                        const html = `
                            <h2>Email Verification OTP</h2>
                            <p>Your OTP code is:</p>
                            <h1>${otpCode}</h1>
                            <p>This code will expire in 10 minutes.</p>
                        `;

                        try {
                            await sendEmail(
                                email,
                                "Your Verification OTP",
                                html
                            );

                            res.status(201).json({
                                message: "Registration successful. OTP sent to email."
                            });

                        } catch (emailError) {
                            res.status(500).json({
                                message: "Failed to send OTP email"
                            });
                        }
                    }
                );
            }
        );

    } catch (error) {
        res.status(500).json({
            message: error.message
        });
    }
};

//verify email
const verifyEmail = (req, res) => {

    try {

        const { token } = req.params;

        db.query(
            "SELECT * FROM users WHERE verification_token = ?",
            [token],
            (err, result) => {

                if (err) {
                    return res.status(500).json(err);
                }

                if (result.length === 0) {
                    return res.status(400).json({
                        message: "Invalid verification token"
                    });
                }

                const user = result[0];

                db.query(
                    `UPDATE users
                    SET is_verified = 1,
                    verification_token = NULL
                    WHERE id = ?`,
                    [user.id],
                    (err) => {

                        if (err) {
                            return res.status(500).json(err);
                        }

                        res.json({
                            message:
                                "Email verified successfully"
                        });

                    }
                );

            }
        );

    } catch (error) {
        res.status(500).json(error);
    }

};

// LOGIN
const login = async (req, res) => {

    try {

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            async (err, result) => {

                if (err) {
                    return res.status(500).json(err);
                }

                if (result.length === 0) {
                    return res.status(400).json({
                        message: "Invalid email or password"
                    });
                }

                const user = result[0];

                if (!user.is_verified) {

                    return res.status(403).json({
                        message:
                            "Please verify your email first"
                    });
                
                }

                const isMatch = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!isMatch) {
                    return res.status(400).json({
                        message: "Invalid email or password"
                    });
                }

                // ACCESS TOKEN
                const accessToken = jwt.sign(
                    {
                        id: user.id,
                        email: user.email
                    },
                    process.env.JWT_SECRET,
                    {
                        expiresIn: "15m"
                    }
                );

                // REFRESH TOKEN
                const refreshToken = jwt.sign(
                    {
                        id: user.id
                    },
                    process.env.REFRESH_SECRET,
                    {
                        expiresIn: "7d"
                    }
                );

                // Save refresh token in DB
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

                        res.status(200).json({
                            message: "Login successful",
                            accessToken,
                            user: {
                                id: user.id,
                                username: user.username,
                                email: user.email
                            }
                        });
                    }
                );
            }
        );

    } catch (error) {
        res.status(500).json(error);
    }

};



//refresh token
const refreshAccessToken = (req, res) => {

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({
            message: "Refresh token required"
        });
    }

    db.query(
        "SELECT * FROM users WHERE refresh_token = ?",
        [refreshToken],
        (err, result) => {

            if (err) {
                return res.status(500).json(err);
            }

            if (result.length === 0) {
                return res.status(403).json({
                    message: "Invalid refresh token"
                });
            }

            jwt.verify(
                refreshToken,
                process.env.REFRESH_SECRET,
                (err, decoded) => {

                    if (err) {
                        return res.status(403).json({
                            message: "Expired refresh token"
                        });
                    }

                    const newAccessToken = jwt.sign(
                        {
                            id: decoded.id
                        },
                        process.env.JWT_SECRET,
                        {
                            expiresIn: "15m"
                        }
                    );

                    res.json({
                        accessToken: newAccessToken
                    });

                }
            );

        }
    );

};

//Forgot Password
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: "Email is required"
            });
        }

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            (err, result) => {
                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                if (result.length === 0) {
                    return res.status(404).json({
                        message: "User not found"
                    });
                }

                const user = result[0];

                const resetToken = crypto.randomBytes(32).toString("hex");

                const expiry = new Date(Date.now() + 1000 * 60 * 15);

                db.query(
                    "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
                    [resetToken, expiry, user.id],
                    async (err) => {
                        if (err) {
                            return res.status(500).json({
                                message: err.message
                            });
                        }

                        const resetLink =
                            `${process.env.FRONTEND_URL}/new-password.html?token=${resetToken}`;


                        const html = `
                            <h2>Password Reset</h2>
                            <p>Click below to reset your password:</p>
                            <a href="${resetLink}">Reset Password</a>
                            <p>This link expires in 15 minutes.</p>
                        `;

                        try {
                            await sendEmail(
                                user.email,
                                "Password Reset",
                                html
                            );

                            return res.json({
                                message: "Password reset email sent"
                            });

                        } catch (emailError) {
                            console.log(emailError);

                            return res.status(500).json({
                                message: "Failed to send password reset email"
                            });
                        }
                    }
                );
            }
        );

    } catch (error) {
        console.log(error);

        return res.status(500).json({
            message: error.message
        });
    }
};

//reset password
const resetPassword = async (req, res) => {

    try {

        const { token, password } = req.body;

        if (!token || !password) {
            return res.status(400).json({
                message: "Token and password required"
            });
        }

        // Password validation
        const passwordRegex =
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

        if (!passwordRegex.test(password)) {

            return res.status(400).json({
                message:
                    "Weak password"
            });

        }

        db.query(
            "SELECT * FROM users WHERE reset_token = ?",
            [token],
            async (err, result) => {

                if (err) {
                    return res.status(500).json(err);
                }

                if (result.length === 0) {
                    return res.status(400).json({
                        message: "Invalid token"
                    });
                }

                const user = result[0];

                if (new Date() > new Date(user.reset_token_expiry)) {

                    return res.status(400).json({
                        message: "Reset token expired"
                    });
                
                }

                const hashedPassword =
                    await bcrypt.hash(password, 10);

                db.query(
                    "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                    [hashedPassword, user.id],
                    (err) => {

                        if (err) {
                            return res.status(500).json(err);
                        }

                        res.json({
                            message: "Password reset successful"
                        });

                    }
                );

            }
        );

    } catch (error) {
        res.status(500).json(error);
    }

};

//otp
const verifyOtp = (req, res) => {

    try {

        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({
                message: "Email and OTP are required"
            });
        }

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            (err, result) => {

                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                if (result.length === 0) {
                    return res.status(404).json({
                        message: "User not found"
                    });
                }

                const user = result[0];

                if (user.is_verified) {
                    return res.status(400).json({
                        message: "Account already verified"
                    });
                }

                if (!user.otp_code || !user.otp_expiry) {
                    return res.status(400).json({
                        message: "No OTP found. Please request a new OTP."
                    });
                }

                if (otp !== user.otp_code) {
                    return res.status(400).json({
                        message: "Invalid OTP"
                    });
                }

                if (new Date() > new Date(user.otp_expiry)) {
                    return res.status(400).json({
                        message: "OTP expired"
                    });
                }

                db.query(
                    `UPDATE users
                    SET is_verified = 1,
                    otp_code = NULL,
                    otp_expiry = NULL
                    WHERE id = ?`,
                    [user.id],
                    (err) => {

                        if (err) {
                            return res.status(500).json({
                                message: err.message
                            });
                        }

                        res.json({
                            message: "Email verified successfully"
                        });

                    }
                );

            }
        );

    } catch (error) {

        console.log(error);

        res.status(500).json({
            message: error.message
        });

    }

};

// RESEND OTP
const resendOtp = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                message: "Email is required"
            });
        }

        db.query(
            "SELECT * FROM users WHERE email = ?",
            [email],
            async (err, result) => {
                if (err) {
                    return res.status(500).json({
                        message: err.message
                    });
                }

                if (result.length === 0) {
                    return res.status(404).json({
                        message: "User not found"
                    });
                }

                const user = result[0];

                if (user.is_verified) {
                    return res.status(400).json({
                        message: "Account is already verified"
                    });
                }

                const otpCode = Math.floor(
                    100000 + Math.random() * 900000
                ).toString();

                const otpExpiry = new Date(Date.now() + 1000 * 60 * 10);

                db.query(
                    `UPDATE users 
                     SET otp_code = ?, otp_expiry = ? 
                     WHERE id = ?`,
                    [otpCode, otpExpiry, user.id],
                    async (err) => {
                        if (err) {
                            return res.status(500).json({
                                message: err.message
                            });
                        }

                        const html = `
                            <h2>New Verification OTP</h2>

                            <p>Your new OTP code is:</p>

                            <h1>${otpCode}</h1>

                            <p>This code will expire in 10 minutes.</p>
                        `;

                        try {
                            await sendEmail(
                                email,
                                "Your New Verification OTP",
                                html
                            );

                            res.json({
                                message: "New OTP sent to email"
                            });

                        } catch (emailError) {
                            console.log(emailError);

                            res.status(500).json({
                                message: "Failed to send OTP email"
                            });
                        }
                    }
                );
            }
        );

    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: error.message
        });
    }
};

module.exports = {
    register,
    login,
    refreshAccessToken,
    forgotPassword,
    resetPassword,
    verifyEmail,
    verifyOtp,
    resendOtp
};