const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');
const Joi = require('joi');

// Validation schemas
const orderItemSchema = Joi.object({
    product_id: Joi.number().integer().required(),
    quantity: Joi.number().integer().min(1).required(),
    unit_price: Joi.number().positive().required(),
    notes: Joi.string().optional()
});

const orderSchema = Joi.object({
    supplier_id: Joi.number().integer().required(),
    order_date: Joi.date().default(new Date()),
    delivery_date: Joi.date().optional(),
    notes: Joi.string().optional(),
    delivery_address: Joi.string().optional(),
    items: Joi.array().items(orderItemSchema).min(1).required()
});

const updateOrderSchema = Joi.object({
    supplier_id: Joi.number().integer().optional(),
    order_date: Joi.date().optional(),
    delivery_date: Joi.date().optional(),
    status: Joi.string().valid('pending', 'confirmed', 'delivered', 'cancelled').optional(),
    notes: Joi.string().optional(),
    delivery_address: Joi.string().optional()
});

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

// Helper function to generate order number
async function generateOrderNumber(tenantId) {
    const year = new Date().getFullYear();
    const count = await db.get(
        'SELECT COUNT(*) as count FROM orders WHERE tenant_id = ? AND order_date >= ?',
        [tenantId, `${year}-01-01`]
    );
    return `ORD-${year}-${String(count.count + 1).padStart(3, '0')}`;
}

// GET /api/orders - Get all orders
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 10, status, supplier_id } = req.query;
        
        let options = {};
        let whereConditions = [];
        let params = [];
        
        // Build where conditions
        if (status) {
            whereConditions.push('status = ?');
            params.push(status);
        }
        
        if (supplier_id) {
            whereConditions.push('supplier_id = ?');
            params.push(supplier_id);
        }
        
        if (whereConditions.length > 0) {
            options.where = whereConditions.join(' AND ');
            options.params = params;
        }
        
        options.orderBy = 'order_date DESC';
        
        const result = await db.paginate('orders', parseInt(page), parseInt(limit), req.tenantId, options);
        
        // Enrich with supplier info and order items
        for (let order of result.items) {
            if (order.supplier_id) {
                order.supplier = await db.get('SELECT * FROM suppliers WHERE id = ?', [order.supplier_id]);
            }
            
            const items = await db.query(
                `SELECT oi.*, p.name as product_name, p.unit 
                 FROM order_items oi 
                 JOIN products p ON oi.product_id = p.id 
                 WHERE oi.order_id = ?`,
                [order.id]
            );
            order.items = items;
        }
        
        res.json(result);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/orders/:id - Get single order
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const order = await db.findById('orders', id, req.tenantId);
        
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        // Enrich with supplier info
        if (order.supplier_id) {
            order.supplier = await db.get('SELECT * FROM suppliers WHERE id = ?', [order.supplier_id]);
        }
        
        // Get order items
        const items = await db.query(
            `SELECT oi.*, p.name as product_name, p.unit, p.article_number 
             FROM order_items oi 
             JOIN products p ON oi.product_id = p.id 
             WHERE oi.order_id = ?`,
            [id]
        );
        order.items = items;
        
        res.json(order);
    } catch (error) {
        console.error('Error fetching order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/orders - Create new order
router.post('/', async (req, res) => {
    try {
        const { error, value } = orderSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({ 
                error: 'Validation error', 
                details: error.details 
            });
        }
        
        // Check if supplier exists
        const supplier = await db.findById('suppliers', value.supplier_id, req.tenantId);
        if (!supplier) {
            return res.status(400).json({ error: 'Supplier not found' });
        }
        
        // Validate products and calculate total
        let totalAmount = 0;
        for (const item of value.items) {
            const product = await db.findById('products', item.product_id, req.tenantId);
            if (!product) {
                return res.status(400).json({ 
                    error: `Product with ID ${item.product_id} not found` 
                });
            }
            item.total_price = item.quantity * item.unit_price;
            totalAmount += item.total_price;
        }
        
        // Use transaction to create order and items
        const order = await db.transaction(async (database) => {
            // Generate order number
            const orderNumber = await generateOrderNumber(req.tenantId);
            
            // Create order
            const orderData = {
                tenant_id: req.tenantId,
                order_number: orderNumber,
                supplier_id: value.supplier_id,
                order_date: value.order_date,
                delivery_date: value.delivery_date,
                status: 'pending',
                total_amount: totalAmount,
                notes: value.notes,
                delivery_address: value.delivery_address
            };
            
            const newOrder = await database.create('orders', orderData);
            
            // Create order items
            for (const item of value.items) {
                await database.create('order_items', {
                    order_id: newOrder.id,
                    product_id: item.product_id,
                    quantity: item.quantity,
                    unit_price: item.unit_price,
                    total_price: item.total_price,
                    notes: item.notes
                });
            }
            
            return newOrder;
        });
        
        // Get the complete order with items
        const completeOrder = await db.findById('orders', order.id, req.tenantId);
        completeOrder.supplier = supplier;
        completeOrder.items = value.items;
        
        res.status(201).json(completeOrder);
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/orders/:id - Update order
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { error, value } = updateOrderSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({ 
                error: 'Validation error', 
                details: error.details 
            });
        }
        
        // Check if order exists
        const existingOrder = await db.findById('orders', id, req.tenantId);
        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        // Check if supplier exists (if being updated)
        if (value.supplier_id) {
            const supplier = await db.findById('suppliers', value.supplier_id, req.tenantId);
            if (!supplier) {
                return res.status(400).json({ error: 'Supplier not found' });
            }
        }
        
        const order = await db.update('orders', id, value, req.tenantId);
        
        // Enrich with supplier info and items
        if (order.supplier_id) {
            order.supplier = await db.get('SELECT * FROM suppliers WHERE id = ?', [order.supplier_id]);
        }
        
        const items = await db.query(
            `SELECT oi.*, p.name as product_name, p.unit 
             FROM order_items oi 
             JOIN products p ON oi.product_id = p.id 
             WHERE oi.order_id = ?`,
            [id]
        );
        order.items = items;
        
        res.json(order);
    } catch (error) {
        console.error('Error updating order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/orders/:id/confirm - Confirm order
router.put('/:id/confirm', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if order exists
        const existingOrder = await db.findById('orders', id, req.tenantId);
        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        if (existingOrder.status !== 'pending') {
            return res.status(400).json({ 
                error: 'Only pending orders can be confirmed' 
            });
        }
        
        const order = await db.update('orders', id, { status: 'confirmed' }, req.tenantId);
        
        res.json({ message: 'Order confirmed successfully', order });
    } catch (error) {
        console.error('Error confirming order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/orders/:id/deliver - Mark order as delivered
router.put('/:id/deliver', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if order exists
        const existingOrder = await db.findById('orders', id, req.tenantId);
        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        if (existingOrder.status !== 'confirmed') {
            return res.status(400).json({ 
                error: 'Only confirmed orders can be delivered' 
            });
        }
        
        // Use transaction to update order status and product stock
        await db.transaction(async (database) => {
            // Update order status
            await database.update('orders', id, { 
                status: 'delivered', 
                delivery_date: new Date() 
            }, req.tenantId);
            
            // Get order items and update product stock
            const items = await database.query(
                'SELECT * FROM order_items WHERE order_id = ?',
                [id]
            );
            
            for (const item of items) {
                // Get current product stock
                const product = await database.get(
                    'SELECT stock FROM products WHERE id = ? AND tenant_id = ?',
                    [item.product_id, req.tenantId]
                );
                
                if (product) {
                    // Update product stock
                    const newStock = product.stock + item.quantity;
                    await database.update('products', item.product_id, { stock: newStock }, req.tenantId);
                    
                    // Create inventory transaction
                    await database.create('inventory_transactions', {
                        tenant_id: req.tenantId,
                        product_id: item.product_id,
                        transaction_type: 'in',
                        quantity: item.quantity,
                        unit_cost: item.unit_price,
                        total_cost: item.total_price,
                        reference_type: 'order',
                        reference_id: id,
                        notes: `Delivery from order ${existingOrder.order_number}`
                    });
                }
            }
        });
        
        const updatedOrder = await db.findById('orders', id, req.tenantId);
        
        res.json({ message: 'Order delivered successfully', order: updatedOrder });
    } catch (error) {
        console.error('Error delivering order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DELETE /api/orders/:id - Cancel order
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if order exists
        const existingOrder = await db.findById('orders', id, req.tenantId);
        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        if (existingOrder.status === 'delivered') {
            return res.status(400).json({ 
                error: 'Cannot cancel delivered orders' 
            });
        }
        
        // Update order status to cancelled instead of deleting
        const order = await db.update('orders', id, { status: 'cancelled' }, req.tenantId);
        
        res.json({ message: 'Order cancelled successfully', order });
    } catch (error) {
        console.error('Error cancelling order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;