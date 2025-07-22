const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');

// GET /api/tenants/current - Get current tenant info
router.get('/current', async (req, res) => {
    try {
        const tenantKey = req.headers['x-tenant-id'] || 'demo';
        
        const tenants = db.data.tenants || [];
        const tenant = tenants.find(t => t.tenant_key === tenantKey);
        
        if (!tenant) {
            return res.status(404).json({ error: 'Tenant not found' });
        }
        
        res.json(tenant);
    } catch (error) {
        console.error('Error fetching tenant:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;