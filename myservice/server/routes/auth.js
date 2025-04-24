const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcrypt');
const db = require('../db');

// User registration
router.post('/register', async (req, res) => {
  const { name, lastname, email, password, role } = req.body;
  
  // Validación de campos requeridos
  if (!name || !lastname || !email || !password) {
    return res.status(400).json({ 
      error: 'Todos los campos son requeridos.',
      fields: {
        name: !name ? 'Nombre es requerido' : null,
        lastname: !lastname ? 'Apellido es requerido' : null,
        email: !email ? 'Email es requerido' : null,
        password: !password ? 'Contraseña es requerida' : null
      }
    });
  }

  // Validación de formato de email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Formato de email inválido' });
  }

  try {
    // Verificar si el email ya existe
    const existingUser = await db.get('SELECT email FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = `${name.toLowerCase()}.${lastname.toLowerCase()}`;
    
    const sql = `INSERT INTO users (
      username, password, email, role, name, lastname
    ) VALUES (?, ?, ?, ?, ?, ?)`;
    
    const params = [
      username,
      hashedPassword,
      email,
      role || 'user',
      name,
      lastname
    ];

    db.run(sql, params, function(err) {
      if (err) {
        console.error('Error en registro:', err.message);
        return res.status(500).json({ error: 'Error al registrar usuario' });
      }

      // Login automático después del registro
      req.login({
        id: this.lastID,
        username,
        email,
        role: role || 'user',
        name,
        lastname
      }, (err) => {
        if (err) {
          console.error('Error en login automático:', err);
          return res.status(500).json({ error: 'Error en autenticación' });
        }
        
        res.status(201).json({ 
          message: 'Registro exitoso',
          user: {
            id: this.lastID,
            username,
            email,
            role: role || 'user',
            name,
            lastname
          }
        });
      });
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
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
