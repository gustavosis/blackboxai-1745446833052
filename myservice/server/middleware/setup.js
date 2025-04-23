const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const path = require('path');
const config = require('../config');
const passport = require('./passport');

module.exports = (app) => {
  // Rate limiting
  const authLimiter = rateLimit(config.rateLimit);

  // Session configuration
  app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  }));

  // Basic middleware
  app.use(bodyParser.json());
  app.use(passport.initialize());
  app.use(passport.session());

  // Serve static files
  app.use(express.static(path.join(__dirname, '../../public')));

  // Apply rate limiter to auth routes
  app.use('/users', authLimiter);
};
