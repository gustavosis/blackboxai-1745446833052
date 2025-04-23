const express = require('express');
const router = express.Router();
const db = require('../db');

// Create service request
router.post('/', (req, res) => {
  const { user_id, provider_id, location } = req.body;
  if (!location) {
    return res.status(400).json({ error: 'Location is required.' });
  }
  const sql = 'INSERT INTO service_requests (user_id, provider_id, location, status, created_at, updated_at) VALUES (?, ?, ?, "pending", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)';
  const params = [user_id || null, provider_id || null, location];
  
  db.run(sql, params, function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to create service request' });
    }
    res.status(201).json({ id: this.lastID, user_id, provider_id, location, status: 'pending' });
  });
});

// Update service request
router.put('/:id', (req, res) => {
  const { id } = req.params;
  const { status, communication, eta } = req.body;
  const sql = 'UPDATE service_requests SET status = COALESCE(?, status), communication = COALESCE(?, communication), eta = COALESCE(?, eta), updated_at = CURRENT_TIMESTAMP WHERE id = ?';
  const params = [status, communication, eta, id];
  
  db.run(sql, params, function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to update service request' });
    }
    res.json({ message: 'Service request updated' });
  });
});

// Get service request by ID
router.get('/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM service_requests WHERE id = ?';
  
  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to fetch service request' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Service request not found' });
    }
    res.json(row);
  });
});

module.exports = router;
