const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');
const Joi = require('joi');

// Validation schemas
const supplierSchema = Joi.object({
    name: Joi.string().required(),
    type: Joi.string().optional(),
    contact_person: Joi.string().optional(),
    email: Joi.string().email().optional(),
    phone: Joi.string().optional(),
    address: Joi.string().optional(),
    rating: Joi.number().min(0).max(5).default(0),
    status: Joi.string().valid('active', 'inactive').default('active')
});

const updateSupplierSchema = supplierSchema.fork(['name'], (schema) => schema.optional());

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

// Apply tenant middleware to all routes
router.use(getTenantId);

// GET /api/suppliers - Get all suppliers
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 10, search, status } = req.query;
        
        let options = {};
        let whereConditions = [];
        let params = [];
        
        // Build where conditions
        if (search) {
            whereConditions.push('(name LIKE ? OR contact_person LIKE ? OR email LIKE ?)');
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }
        
        if (status) {
            whereConditions.push('status = ?');
            params.push(status);
        }
        
        if (whereConditions.length > 0) {
            options.where = whereConditions.join(' AND ');
            options.params = params;
        }
        
        options.orderBy = 'name ASC';
        
        const result = await db.paginate('suppliers', parseInt(page), parseInt(limit), req.tenantId, options);
        
        // Enrich with product count
        for (let supplier of result.items) {
            const productCount = await db.get(
                'SELECT COUNT(*) as count FROM products WHERE supplier_id = ? AND tenant_id = ?',
                [supplier.id, req.tenantId]
            );
            supplier.products_count = productCount.count;
        }
        
        res.json(result);
    } catch (error) {
        console.error('Error fetching suppliers:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/suppliers/:id - Get single supplier
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const supplier = await db.findById('suppliers', id, req.tenantId);
        
        if (!supplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        // Get supplier's products
        const products = await db.query(
            'SELECT * FROM products WHERE supplier_id = ? AND tenant_id = ? ORDER BY name ASC',
            [id, req.tenantId]
        );
        
        supplier.products = products;
        supplier.products_count = products.length;
        
        res.json(supplier);
    } catch (error) {
        console.error('Error fetching supplier:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/suppliers - Create new supplier
router.post('/', async (req, res) => {
    try {
        const { error, value } = supplierSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({ 
                error: 'Validation error', 
                details: error.details 
            });
        }
        
        // Check if supplier name already exists
        const existingSupplier = await db.get(
            'SELECT id FROM suppliers WHERE name = ? AND tenant_id = ?',
            [value.name, req.tenantId]
        );
        
        if (existingSupplier) {
            return res.status(400).json({ 
                error: 'Supplier name already exists' 
            });
        }
        
        // Add tenant_id to supplier data
        value.tenant_id = req.tenantId;
        value.products_count = 0;
        
        const supplier = await db.create('suppliers', value);
        
        res.status(201).json(supplier);
    } catch (error) {
        console.error('Error creating supplier:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/suppliers/:id - Update supplier
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error, value } = updateSupplierSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({ 
                error: 'Validation error', 
                details: error.details 
            });
        }
        
        // Check if supplier exists
        const existingSupplier = await db.findById('suppliers', id, req.tenantId);
        if (!existingSupplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        // Check if supplier name already exists (if being updated)
        if (value.name && value.name !== existingSupplier.name) {
            const duplicateSupplier = await db.get(
                'SELECT id FROM suppliers WHERE name = ? AND tenant_id = ? AND id != ?',
                [value.name, req.tenantId, id]
            );
            
            if (duplicateSupplier) {
                return res.status(400).json({ 
                    error: 'Supplier name already exists' 
                });
            }
        }
        
        const supplier = await db.update('suppliers', id, value, req.tenantId);
        
        res.json(supplier);
    } catch (error) {
        console.error('Error updating supplier:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/suppliers/:id - Delete supplier
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if supplier exists
        const existingSupplier = await db.findById('suppliers', id, req.tenantId);
        if (!existingSupplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        // Check if supplier has products
        const hasProducts = await db.get(
            'SELECT COUNT(*) as count FROM products WHERE supplier_id = ? AND tenant_id = ?',
            [id, req.tenantId]
        );
        
        if (hasProducts.count > 0) {
            return res.status(400).json({ 
                error: 'Cannot delete supplier that has products' 
            });
        }
        
        const deleted = await db.delete('suppliers', id, req.tenantId);
        
        if (deleted) {
            res.status(204).send();
        } else {
            res.status(404).json({ error: 'Supplier not found' });
        }
    } catch (error) {
        console.error('Error deleting supplier:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/suppliers/:id/rate - Rate a supplier
router.post('/:id/rate', async (req, res) => {
    try {
        const { id } = req.params;
        const { rating, comment } = req.body;
        
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ 
                error: 'Rating must be between 1 and 5' 
            });
        }
        
        // Check if supplier exists
        const supplier = await db.findById('suppliers', id, req.tenantId);
        if (!supplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        // Update supplier rating (simple average for now)
        const updatedSupplier = await db.update('suppliers', id, { rating }, req.tenantId);
        
        // In a real app, you'd store individual ratings in a separate table
        // For now, we'll just update the average rating
        
        res.json({
            message: 'Supplier rated successfully',
            supplier: updatedSupplier,
            rating,
            comment
        });
        
    } catch (error) {
        console.error('Error rating supplier:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/suppliers/:id/products - Get supplier's products
router.get('/:id/products', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if supplier exists
        const supplier = await db.findById('suppliers', id, req.tenantId);
        if (!supplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        const products = await db.query(
            `SELECT p.*, pc.name as category_name 
             FROM products p 
             LEFT JOIN product_categories pc ON p.category_id = pc.id
             WHERE p.supplier_id = ? AND p.tenant_id = ? 
             ORDER BY p.name ASC`,
            [id, req.tenantId]
        );
        
        res.json(products);
    } catch (error) {
        console.error('Error fetching supplier products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/suppliers/:id/orders - Get supplier's orders
router.get('/:id/orders', async (req, res) => {
    try {
        const { id } = req.params;
        const { page = 1, limit = 10 } = req.query;
        
        // Check if supplier exists
        const supplier = await db.findById('suppliers', id, req.tenantId);
        if (!supplier) {
            return res.status(404).json({ error: 'Supplier not found' });
        }
        
        const options = {
            where: 'supplier_id = ?',
            params: [id],
            orderBy: 'order_date DESC'
        };
        
        const result = await db.paginate('orders', parseInt(page), parseInt(limit), req.tenantId, options);
        
        // Enrich with order items
        for (let order of result.items) {
            const items = await db.query(
                `SELECT oi.*, p.name as product_name 
                 FROM order_items oi 
                 JOIN products p ON oi.product_id = p.id 
                 WHERE oi.order_id = ?`,
                [order.id]
            );
            order.items = items;
        }
        
        res.json(result);
    } catch (error) {
        console.error('Error fetching supplier orders:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;