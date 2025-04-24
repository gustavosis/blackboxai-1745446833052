const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcrypt');
const db = require('../db');

// User registration
router.post('/register', async (req, res) => {
  const { username, password, email, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)";
    const params = [username, hashedPassword, email || '', role || 'user'];
    db.run(sql, params, function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Failed to register user' });
      }
      res.status(201).json({ id: this.lastID, username, email, role: role || 'user' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error hashing password' });
  }
});

// User login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) { return res.status(401).json({ error: 'Invalid credentials' }); }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      return res.json({ 
        message: 'Login successful', 
        user: { 
          id: user.id, 
          username: user.username, 
          email: user.email, 
          role: user.role 
        } 
      });
    });
  })(req, res, next);
});

// Google OAuth login
router.get('/google', passport.authenticate('google', { 
  scope: ['profile', 'email'],
  prompt: 'select_account' // Permite seleccionar cuenta cada vez
}));

// Google OAuth callback
router.get('/google/callback', 
  passport.authenticate('google', { 
    failureRedirect: '/login?error=auth_failed',
    failureFlash: true
  }),
  (req, res) => {
    const role = req.user.role || 'user';
    res.redirect(`/${role}/dashboard`);
  }
);

// Facebook OAuth login
router.get('/facebook', passport.authenticate('facebook', { 
  scope: ['email'],
  authType: 'rerequest' // Solicita permisos nuevamente si fueron denegados
}));

// Facebook OAuth callback
router.get('/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/login?error=auth_failed',
    failureFlash: true
  }),
  (req, res) => {
    const role = req.user.role || 'user';
    res.redirect(`/${role}/dashboard`);
  }
);

// Logout route
router.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login?message=logged_out');
});

module.exports = router;
