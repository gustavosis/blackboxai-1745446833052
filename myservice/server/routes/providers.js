const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcrypt');

// Register provider and user
router.post('/', async (req, res) => {
  const { name, service, description, contact, location, latitude, longitude, password, email } = req.body;
  if (!name || !service || !contact || !password || !email) {
    return res.status(400).json({ error: 'Name, service, contact, email, and password are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userSql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    const userParams = [contact, hashedPassword, email];
    db.run(userSql, userParams, function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Failed to register user' });
      }
      const userId = this.lastID;
      const providerSql = 'INSERT INTO providers (name, service, description, contact, location, latitude, longitude, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)';
      const providerParams = [name, service.toLowerCase(), description || '', contact, location || '', parseFloat(latitude) || null, parseFloat(longitude) || null];
      db.run(providerSql, providerParams, function(err) {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: 'Failed to register provider' });
        }
        res.status(201).json({ userId, providerId: this.lastID, active: 1 });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Upload provider documents
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'video/webm', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de archivo no permitido'), false);
    }
  },
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 5
  }
});

router.post('/:id/documents', upload.array('documents', 10), (req, res) => {
  const providerId = req.params.id;
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  const stmt = db.prepare('INSERT INTO provider_documents (provider_id, type, file_path) VALUES (?, ?, ?)');
  req.files.forEach(file => {
    let type = 'photo';
    if (file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
      type = 'photo';
    } else if (file.originalname.match(/\.(pdf|doc|docx)$/i)) {
      type = 'diploma';
    } else if (file.originalname.match(/\.(mp4|webm)$/i)) {
      type = 'video';
    }
    stmt.run(providerId, type, file.filename);
  });
  stmt.finalize(err => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to save documents' });
    }
    res.status(201).json({ message: 'Documents uploaded successfully' });
  });
});

// Upload provider video
router.post('/:id/video', upload.single('video'), (req, res) => {
  const providerId = req.params.id;
  if (!req.file) {
    return res.status(400).json({ error: 'No video file uploaded' });
  }
  if (!req.file.mimetype.startsWith('video/')) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'Invalid file type. Only video files are allowed.' });
  }
  db.run('INSERT INTO provider_documents (provider_id, type, file_path) VALUES (?, "video", ?)', [providerId, req.file.filename], function(err) {
    if (err) {
      console.error(err.message);
      fs.unlink(req.file.path, () => {});
      return res.status(500).json({ error: 'Failed to save video information' });
    }
    res.status(201).json({ message: 'Video uploaded successfully', videoId: this.lastID, filename: req.file.filename });
  });
});

// Get provider video
router.get('/:id/video', (req, res) => {
  const providerId = req.params.id;
  db.get('SELECT file_path FROM provider_documents WHERE provider_id = ? AND type = "video" ORDER BY uploaded_at DESC LIMIT 1', [providerId], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to fetch video information' });
    }
    if (!row) {
      return res.status(404).json({ error: 'No video found for this provider' });
    }
    const videoPath = path.join(__dirname, '..', 'uploads', row.file_path);
    if (!fs.existsSync(videoPath)) {
      return res.status(404).json({ error: 'Video file not found' });
    }
    res.sendFile(videoPath);
  });
});

// Get providers with optional search and location filtering
router.get('/', (req, res) => {
  const search = (req.query.search || '').toLowerCase();
  const lat = parseFloat(req.query.lat);
  const lng = parseFloat(req.query.lng);
  const radius = parseFloat(req.query.radius) || 10;

  let sql = "SELECT * FROM providers WHERE active = 1";
  let params = [];

  if (search) {
    sql += " AND service LIKE ?";
    params.push("%" + search + "%");
  }

  // Add distance calculation only if coordinates are provided
  if (!isNaN(lat) && !isNaN(lng)) {
    sql = `SELECT *, 
      (6371 * acos(cos(radians(?)) * cos(radians(latitude)) * 
      cos(radians(longitude) - radians(?)) + sin(radians(?)) * 
      sin(radians(latitude)))) AS distance 
      FROM (${sql})
      WHERE latitude IS NOT NULL AND longitude IS NOT NULL
      HAVING distance <= ?
      ORDER BY distance ASC`;
    params = [lat, lng, lat, ...params, radius];
  }

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to fetch providers' });
    }
    res.json(rows);
  });
});

module.exports = router;
