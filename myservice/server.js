const express = require('express');
const path = require('path');
const fs = require('fs');
const config = require('./server/config');
const db = require('./server/db');
const app = express();

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir);
}

// Setup middleware
require('./server/middleware/setup')(app);

// Initialize database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    description TEXT,
    contact TEXT NOT NULL,
    location TEXT,
    latitude REAL,
    longitude REAL,
    active INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS service_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    provider_id INTEGER,
    location TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    communication TEXT,
    eta TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(provider_id) REFERENCES providers(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS provider_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(provider_id) REFERENCES providers(id)
  )`);
});

// Routes
app.use('/auth', require('./server/routes/auth'));
app.use('/providers', require('./server/routes/providers'));
app.use('/service-requests', require('./server/routes/service-requests'));

// Serve index.html on root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(config.port, () => {
  console.log(`Service Directory API listening at http://localhost:${config.port}`);
});
