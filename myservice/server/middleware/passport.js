const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');
const db = require('../db');
const config = require('../config');

passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
      if (!user) return done(null, false);
      const isValid = await bcrypt.compare(password, user.password);
      return isValid ? done(null, user) : done(null, false);
    } catch (err) {
      return done(err);
    }
  }
));

passport.use(new GoogleStrategy({
    clientID: config.oauth.google.clientID,
    clientSecret: config.oauth.google.clientSecret,
    callbackURL: config.oauth.google.callbackURL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await db.get('SELECT * FROM users WHERE googleId = ?', [profile.id]);
      if (!user) {
        await db.run(
          'INSERT INTO users (googleId, email, username) VALUES (?, ?, ?)',
          [profile.id, profile.emails[0].value, profile.displayName]
        );
        user = await db.get('SELECT * FROM users WHERE googleId = ?', [profile.id]);
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.use(new FacebookStrategy({
    clientID: config.oauth.facebook.clientID,
    clientSecret: config.oauth.facebook.clientSecret,
    callbackURL: config.oauth.facebook.callbackURL,
    profileFields: ['id', 'emails', 'name']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await db.get('SELECT * FROM users WHERE facebookId = ?', [profile.id]);
      if (!user) {
        await db.run(
          'INSERT INTO users (facebookId, email, username) VALUES (?, ?, ?)',
          [profile.id, profile.emails[0].value, profile.displayName]
        );
        user = await db.get('SELECT * FROM users WHERE facebookId = ?', [profile.id]);
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
});

module.exports = passport;
