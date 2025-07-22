const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');

// Helper function to get tenant ID
function getTenantId(req, res, next) {
    const tenantKey = req.headers['x-tenant-id'] || 'demo';
    
    // Use findAll method compatible with in-memory database
    const tenants = db.data.tenants || [];
    const tenant = tenants.find(t => t.tenant_key === tenantKey);
    
    if (!tenant) {
        return res.status(404).json({ error: 'Tenant not found' });
    }
    
    req.tenantId = tenant.id;
    next();
}

router.use(getTenantId);

// GET /api/inventory - Get inventory overview
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 10, search, category, status } = req.query;
        
        let options = {};
        let whereConditions = [];
        let params = [];
        
        if (search) {
            whereConditions.push('(p.name LIKE ? OR p.article_number LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }
        
        if (category) {
            whereConditions.push('p.category_id = ?');
            params.push(category);
        }
        
        if (status === 'low') {
            whereConditions.push('p.stock <= p.min_stock');
        } else if (status === 'high') {
            whereConditions.push('p.stock > p.min_stock');
        }
        
        let sql = `
            SELECT p.*, 
                   pc.name as category_name, 
                   s.name as supplier_name,
                   CASE 
                       WHEN p.stock <= p.min_stock THEN 'low'
                       WHEN p.stock > p.min_stock * 2 THEN 'high'
                       ELSE 'normal'
                   END as stock_status
            FROM products p 
            LEFT JOIN product_categories pc ON p.category_id = pc.id
            LEFT JOIN suppliers s ON p.supplier_id = s.id
            WHERE p.tenant_id = ?
        `;
        
        params.unshift(req.tenantId);
        
        if (whereConditions.length > 0) {
            sql += ' AND ' + whereConditions.join(' AND ');
        }
        
        sql += ' ORDER BY p.name ASC';
        
        const offset = (page - 1) * limit;
        sql += ` LIMIT ${limit} OFFSET ${offset}`;
        
        const products = await db.query(sql, params);
        
        // Get total count
        let countSql = 'SELECT COUNT(*) as count FROM products p WHERE p.tenant_id = ?';
        let countParams = [req.tenantId];
        
        if (whereConditions.length > 0) {
            countSql += ' AND ' + whereConditions.join(' AND ');
            countParams = countParams.concat(params.slice(1));
        }
        
        const countResult = await db.get(countSql, countParams);
        const totalItems = countResult.count;
        const totalPages = Math.ceil(totalItems / limit);
        
        res.json({
            items: products,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalItems,
                totalPages,
                hasNextPage: page < totalPages,
                hasPreviousPage: page > 1
            }
        });
    } catch (error) {
        console.error('Error fetching inventory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/inventory/transactions - Get inventory transactions
router.get('/transactions', async (req, res) => {
    try {
        const { page = 1, limit = 10, product_id, type } = req.query;
        
        let options = {};
        let whereConditions = [];
        let params = [];
        
        if (product_id) {
            whereConditions.push('product_id = ?');
            params.push(product_id);
        }
        
        if (type) {
            whereConditions.push('transaction_type = ?');
            params.push(type);
        }
        
        if (whereConditions.length > 0) {
            options.where = whereConditions.join(' AND ');
            options.params = params;
        }
        
        options.orderBy = 'created_at DESC';
        
        const result = await db.paginate('inventory_transactions', parseInt(page), parseInt(limit), req.tenantId, options);
        
        // Enrich with product info
        for (let transaction of result.items) {
            if (transaction.product_id) {
                transaction.product = await db.get('SELECT * FROM products WHERE id = ?', [transaction.product_id]);
            }
        }
        
        res.json(result);
    } catch (error) {
        console.error('Error fetching inventory transactions:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/inventory/summary - Get inventory summary
router.get('/summary', async (req, res) => {
    try {
        const summary = await db.query(`
            SELECT 
                COUNT(*) as total_products,
                SUM(CASE WHEN stock <= min_stock THEN 1 ELSE 0 END) as low_stock_count,
                SUM(stock * price) as total_value,
                AVG(stock) as avg_stock
            FROM products 
            WHERE tenant_id = ? AND status = 'active'
        `, [req.tenantId]);
        
        const topProducts = await db.query(`
            SELECT p.name, p.stock, p.price, p.stock * p.price as value
            FROM products p
            WHERE p.tenant_id = ? AND p.status = 'active'
            ORDER BY value DESC
            LIMIT 5
        `, [req.tenantId]);
        
        const lowStockProducts = await db.query(`
            SELECT p.name, p.stock, p.min_stock, p.article_number
            FROM products p
            WHERE p.tenant_id = ? AND p.stock <= p.min_stock
            ORDER BY p.stock ASC
            LIMIT 10
        `, [req.tenantId]);
        
        res.json({
            summary: summary[0],
            topProducts,
            lowStockProducts
        });
    } catch (error) {
        console.error('Error fetching inventory summary:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;