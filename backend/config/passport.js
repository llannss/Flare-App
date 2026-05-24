const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const db = require("./db");

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "http://localhost:8000/api/auth/google/callback"
        },

        (accessToken, refreshToken, profile, done) => {
            const email = profile.emails?.[0]?.value;
            const username = profile.displayName;

            if (!email) {
                return done(new Error("No email found from Google account"), null);
            }

            db.query(
                "SELECT * FROM users WHERE email = ?",
                [email],
                (err, result) => {
                    if (err) {
                        return done(err, null);
                    }

                    if (result.length > 0) {
                        const user = result[0];

                        db.query(
                            "UPDATE users SET is_verified = 1 WHERE id = ?",
                            [user.id],
                            (err) => {
                                if (err) {
                                    return done(err, null);
                                }

                                user.is_verified = 1;

                                return done(null, {
                                    id: user.id,
                                    username: user.username,
                                    email: user.email,
                                    is_verified: user.is_verified
                                });
                            }
                        );

                        return;
                    }

                    db.query(
                        `INSERT INTO users
                        (username, email, password, is_verified, provider, provider_id)
                        VALUES (?, ?, NULL, 1, ?, ?)`,
                        [
                            username,
                            email,
                            "google",
                            profile.id
                        ],
                        (err, result) => {
                            if (err) {
                                return done(err, null);
                            }

                            const user = {
                                id: result.insertId,
                                username,
                                email,
                                is_verified: 1,
                                provider: "google",
                                provider_id: profile.id
                            };

                            return done(null, user);
                        }
                    );
                }
            );
        }
    )
);

module.exports = passport;