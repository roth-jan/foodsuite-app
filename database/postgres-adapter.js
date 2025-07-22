const db = require('./postgres-client');

// PostgreSQL adapter that mimics the in-memory database interface
class PostgresAdapter {
    constructor() {
        this.initialized = false;
    }
    
    async initialize() {
        if (!this.initialized) {
            await db.testConnection();
            await db.createTables();
            this.initialized = true;
        }
    }
    
    // Products
    async getProducts(tenantId, filters = {}) {
        let query = 'SELECT p.*, s.* FROM products p LEFT JOIN suppliers s ON p.supplier_id = s.id WHERE p.tenant_id = $1';
        const params = [tenantId];
        let paramCount = 1;
        
        if (filters.category) {
            paramCount++;
            query += ` AND p.category = $${paramCount}`;
            params.push(filters.category);
        }
        
        if (filters.search) {
            paramCount++;
            query += ` AND p.name ILIKE $${paramCount}`;
            params.push(`%${filters.search}%`);
        }
        
        query += ' ORDER BY p.id';
        
        if (filters.limit) {
            paramCount++;
            query += ` LIMIT $${paramCount}`;
            params.push(filters.limit);
        }
        
        if (filters.offset) {
            paramCount++;
            query += ` OFFSET $${paramCount}`;
            params.push(filters.offset);
        }
        
        const result = await db.query(query, params);
        
        // Format results to match expected structure
        return result.rows.map(row => ({
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            category: row.category,
            unit: row.unit,
            price: parseFloat(row.price),
            stock: row.stock,
            min_stock: row.min_stock,
            max_stock: row.max_stock,
            supplier_id: row.supplier_id,
            storage_location: row.storage_location,
            supplier: row.supplier_id ? {
                id: row.supplier_id,
                name: result.rows.find(r => r.supplier_id === row.supplier_id)?.name || '',
                contact_person: result.rows.find(r => r.supplier_id === row.supplier_id)?.contact_person || '',
                email: result.rows.find(r => r.supplier_id === row.supplier_id)?.email || ''
            } : null
        }));
    }
    
    async getProduct(tenantId, productId) {
        const query = `
            SELECT p.*, s.id as supplier_id, s.name as supplier_name, s.contact_person, s.email, s.phone, s.rating 
            FROM products p 
            LEFT JOIN suppliers s ON p.supplier_id = s.id 
            WHERE p.tenant_id = $1 AND p.id = $2
        `;
        const result = await db.query(query, [tenantId, productId]);
        
        if (result.rows.length === 0) return null;
        
        const row = result.rows[0];
        return {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            category: row.category,
            unit: row.unit,
            price: parseFloat(row.price),
            stock: row.stock,
            min_stock: row.min_stock,
            max_stock: row.max_stock,
            supplier_id: row.supplier_id,
            storage_location: row.storage_location,
            supplier: row.supplier_id ? {
                id: row.supplier_id,
                name: row.supplier_name,
                contact_person: row.contact_person,
                email: row.email,
                phone: row.phone,
                rating: parseFloat(row.rating)
            } : null
        };
    }
    
    async createProduct(tenantId, productData) {
        const query = `
            INSERT INTO products (tenant_id, name, category, unit, price, stock, min_stock, max_stock, supplier_id, storage_location)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        `;
        const result = await db.query(query, [
            tenantId,
            productData.name,
            productData.category,
            productData.unit,
            productData.price,
            productData.stock || 0,
            productData.min_stock || 0,
            productData.max_stock || 1000,
            productData.supplier_id || null,
            productData.storage_location || ''
        ]);
        
        return this.getProduct(tenantId, result.rows[0].id);
    }
    
    async updateProduct(tenantId, productId, updates) {
        const fields = [];
        const values = [];
        let paramCount = 0;
        
        Object.entries(updates).forEach(([key, value]) => {
            if (key !== 'id' && key !== 'tenant_id') {
                paramCount++;
                fields.push(`${key} = $${paramCount}`);
                values.push(value);
            }
        });
        
        if (fields.length === 0) return this.getProduct(tenantId, productId);
        
        paramCount++;
        values.push(tenantId);
        paramCount++;
        values.push(productId);
        
        const query = `
            UPDATE products 
            SET ${fields.join(', ')}, created_at = created_at 
            WHERE tenant_id = $${paramCount - 1} AND id = $${paramCount}
        `;
        
        await db.query(query, values);
        return this.getProduct(tenantId, productId);
    }
    
    async deleteProduct(tenantId, productId) {
        await db.query('DELETE FROM products WHERE tenant_id = $1 AND id = $2', [tenantId, productId]);
    }
    
    // Recipes
    async getRecipes(tenantId, filters = {}) {
        let query = 'SELECT * FROM recipes WHERE tenant_id = $1';
        const params = [tenantId];
        let paramCount = 1;
        
        if (filters.category) {
            paramCount++;
            query += ` AND category = $${paramCount}`;
            params.push(filters.category);
        }
        
        if (filters.search) {
            paramCount++;
            query += ` AND name ILIKE $${paramCount}`;
            params.push(`%${filters.search}%`);
        }
        
        query += ' ORDER BY id';
        
        if (filters.limit) {
            paramCount++;
            query += ` LIMIT $${paramCount}`;
            params.push(filters.limit);
        }
        
        const result = await db.query(query, params);
        
        return result.rows.map(row => ({
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            category: row.category,
            portions: row.portions,
            prep_time: row.prep_time,
            cook_time: row.cook_time,
            cost_per_portion: parseFloat(row.cost_per_portion),
            instructions: row.instructions,
            tags: row.tags
        }));
    }
    
    async getRecipe(tenantId, recipeId) {
        const result = await db.query('SELECT * FROM recipes WHERE tenant_id = $1 AND id = $2', [tenantId, recipeId]);
        if (result.rows.length === 0) return null;
        
        const row = result.rows[0];
        return {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            category: row.category,
            portions: row.portions,
            prep_time: row.prep_time,
            cook_time: row.cook_time,
            cost_per_portion: parseFloat(row.cost_per_portion),
            instructions: row.instructions,
            tags: row.tags
        };
    }
    
    async createRecipe(tenantId, recipeData) {
        const query = `
            INSERT INTO recipes (tenant_id, name, category, portions, prep_time, cook_time, cost_per_portion, instructions, tags)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        `;
        const result = await db.query(query, [
            tenantId,
            recipeData.name,
            recipeData.category,
            recipeData.portions,
            recipeData.prep_time,
            recipeData.cook_time,
            recipeData.cost_per_portion,
            recipeData.instructions || '',
            recipeData.tags || ''
        ]);
        
        return this.getRecipe(tenantId, result.rows[0].id);
    }
    
    // Suppliers
    async getSuppliers(tenantId, filters = {}) {
        let query = 'SELECT * FROM suppliers WHERE tenant_id = $1';
        const params = [tenantId];
        
        if (filters.search) {
            query += ' AND name ILIKE $2';
            params.push(`%${filters.search}%`);
        }
        
        query += ' ORDER BY id';
        
        if (filters.limit) {
            query += ` LIMIT $${params.length + 1}`;
            params.push(filters.limit);
        }
        
        const result = await db.query(query, params);
        
        return result.rows.map(row => ({
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            type: row.type,
            contact_person: row.contact_person,
            email: row.email,
            phone: row.phone,
            address: row.address,
            products_count: row.products_count || 0,
            rating: parseFloat(row.rating || 0),
            status: row.status
        }));
    }
    
    // Orders
    async getOrders(tenantId, filters = {}) {
        let query = `
            SELECT o.*, s.name as supplier_name 
            FROM orders o 
            LEFT JOIN suppliers s ON o.supplier_id = s.id 
            WHERE o.tenant_id = $1
        `;
        const params = [tenantId];
        
        query += ' ORDER BY o.id DESC';
        
        if (filters.limit) {
            query += ` LIMIT $${params.length + 1}`;
            params.push(filters.limit);
        }
        
        const result = await db.query(query, params);
        
        return result.rows.map(row => ({
            id: row.id,
            tenant_id: row.tenant_id,
            supplier_id: row.supplier_id,
            supplier_name: row.supplier_name,
            order_date: row.order_date,
            delivery_date: row.delivery_date,
            status: row.status,
            total_amount: parseFloat(row.total_amount || 0),
            notes: row.notes
        }));
    }
    
    // Inventory
    async getInventory(tenantId) {
        const query = `
            SELECT i.*, p.name as product_name, p.category, p.unit 
            FROM inventory i 
            JOIN products p ON i.product_id = p.id 
            WHERE i.tenant_id = $1
        `;
        const result = await db.query(query, [tenantId]);
        
        return result.rows.map(row => ({
            id: row.id,
            tenant_id: row.tenant_id,
            product_id: row.product_id,
            product_name: row.product_name,
            category: row.category,
            unit: row.unit,
            quantity: parseFloat(row.quantity),
            last_updated: row.last_updated,
            notes: row.notes
        }));
    }
    
    // Dashboard stats
    async getDashboardStats(tenantId) {
        const [products, recipes, suppliers, orders, lowStock] = await Promise.all([
            db.query('SELECT COUNT(*) FROM products WHERE tenant_id = $1', [tenantId]),
            db.query('SELECT COUNT(*) FROM recipes WHERE tenant_id = $1', [tenantId]),
            db.query('SELECT COUNT(*) FROM suppliers WHERE tenant_id = $1', [tenantId]),
            db.query('SELECT COUNT(*) FROM orders WHERE tenant_id = $1', [tenantId]),
            db.query('SELECT COUNT(*) FROM products WHERE tenant_id = $1 AND stock < min_stock', [tenantId])
        ]);
        
        return {
            totalProducts: parseInt(products.rows[0].count),
            totalRecipes: parseInt(recipes.rows[0].count),
            totalSuppliers: parseInt(suppliers.rows[0].count),
            totalOrders: parseInt(orders.rows[0].count),
            lowStockItems: parseInt(lowStock.rows[0].count)
        };
    }
    
    // Meal plans
    async getMealPlans(tenantId, weekNumber, year) {
        const query = `
            SELECT mp.*, r.name as recipe_name, r.category, r.cost_per_portion, r.tags 
            FROM meal_plans mp 
            JOIN recipes r ON mp.recipe_id = r.id 
            WHERE mp.tenant_id = $1 AND mp.week_number = $2 AND mp.year = $3
        `;
        const result = await db.query(query, [tenantId, weekNumber, year]);
        
        const mealPlan = {};
        result.rows.forEach(row => {
            const key = `${row.day_of_week}-${row.meal_type}`;
            mealPlan[key] = {
                id: row.recipe_id,
                name: row.recipe_name,
                category: row.category,
                cost_per_portion: parseFloat(row.cost_per_portion),
                tags: row.tags,
                servings: row.servings
            };
        });
        
        return mealPlan;
    }
    
    async saveMealPlan(tenantId, weekNumber, year, mealPlan) {
        // Delete existing meal plan
        await db.query(
            'DELETE FROM meal_plans WHERE tenant_id = $1 AND week_number = $2 AND year = $3',
            [tenantId, weekNumber, year]
        );
        
        // Insert new meal plan
        for (const [slot, recipe] of Object.entries(mealPlan)) {
            const [day, mealType] = slot.split('-');
            await db.query(
                `INSERT INTO meal_plans (tenant_id, week_number, year, day_of_week, meal_type, recipe_id, servings)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [tenantId, weekNumber, year, day, mealType, recipe.id, recipe.servings || recipe.portions || 100]
            );
        }
    }
}

module.exports = new PostgresAdapter();