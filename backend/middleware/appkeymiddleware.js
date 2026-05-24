const verifyAppKey = (req, res, next) => {
    const appKey = req.headers["x-app-key"];

    if (!appKey) {
        return res.status(401).json({
            message: "App key is required"
        });
    }

    if (appKey !== process.env.APP_KEY) {
        return res.status(403).json({
            message: "Invalid app key"
        });
    }

    next();
};

module.exports = verifyAppKey;