const { body, validationResult } = require("express-validator");

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({
            message: errors.array()[0].msg
        });
    }

    next();
};

const registerValidation = [
    body("username")
        .notEmpty()
        .withMessage("Username is required")
        .isLength({ min: 3 })
        .withMessage("Username must be at least 3 characters"),

    body("email")
        .isEmail()
        .withMessage("Valid email is required"),

    body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters")
        .matches(/[a-z]/)
        .withMessage("Password must include lowercase letter")
        .matches(/[A-Z]/)
        .withMessage("Password must include uppercase letter")
        .matches(/\d/)
        .withMessage("Password must include number")
        .matches(/[@$!%*?&]/)
        .withMessage("Password must include special character"),

    handleValidationErrors
];

const loginValidation = [
    body("email")
        .isEmail()
        .withMessage("Valid email is required"),

    body("password")
        .notEmpty()
        .withMessage("Password is required"),

    handleValidationErrors
];

const emailValidation = [
    body("email")
        .isEmail()
        .withMessage("Valid email is required"),

    handleValidationErrors
];

const otpValidation = [
    body("email")
        .isEmail()
        .withMessage("Valid email is required"),

    body("otp")
        .isLength({ min: 6, max: 6 })
        .withMessage("OTP must be 6 digits")
        .isNumeric()
        .withMessage("OTP must contain numbers only"),

    handleValidationErrors
];

const resetPasswordValidation = [
    body("token")
        .notEmpty()
        .withMessage("Token is required"),

    body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters")
        .matches(/[a-z]/)
        .withMessage("Password must include lowercase letter")
        .matches(/[A-Z]/)
        .withMessage("Password must include uppercase letter")
        .matches(/\d/)
        .withMessage("Password must include number")
        .matches(/[@$!%*?&]/)
        .withMessage("Password must include special character"),

    handleValidationErrors
];

module.exports = {
    registerValidation,
    loginValidation,
    emailValidation,
    otpValidation,
    resetPasswordValidation
};