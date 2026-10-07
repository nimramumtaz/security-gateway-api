const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const usersDb = require("../data/users");

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, usersDb.findById(id)));

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      // Check if this Google account is already linked to a user
      let user = usersDb.findByGoogleId(profile.id);

      if (!user) {
        // Check if email already exists as a local account -> sync/link it
        const email = profile.emails && profile.emails[0] && profile.emails[0].value;
        user = email ? usersDb.findByEmail(email) : null;

        if (user) {
          // Link Google ID to existing local account
          user.googleId = profile.id;
          user.provider = "google";
        } else {
          // Brand new user via OAuth -> default role = Employee
          user = usersDb.addUser({
            email: email || `google_${profile.id}@no-email.com`,
            password: null,
            role: "Employee",
            provider: "google",
            googleId: profile.id,
          });
        }
      }

      return done(null, user);
    }
  )
);

module.exports = passport;
