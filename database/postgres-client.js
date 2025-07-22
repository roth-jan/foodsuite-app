const { Pool } = require('pg');

// PostgreSQL connection configuration
const pgConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5433,
    database: process.env.DB_NAME || 'foodsuite',
    user: process.env.DB_USER || 'foodsuite',
    password: process.env.DB_PASSWORD || 'foodsuite123',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
};

const pool = new Pool(pgConfig);

// Test connection
pool.on('connect', () => {
    console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
    console.error('❌ PostgreSQL pool error:', err);
});

module.exports = {
    query: (text, params) => pool.query(text, params),
    pool,
    
    // Helper functions
    testConnection: async function() {
        try {
            const result = await pool.query('SELECT NOW()');
            console.log('✅ PostgreSQL connection test successful:', result.rows[0].now);
            return true;
        } catch (error) {
            console.error('❌ PostgreSQL connection test failed:', error);
            return false;
        }
    },
    
    createTables: async function() {
        const queries = [
            // Tenants table
            `CREATE TABLE IF NOT EXISTS tenants (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Suppliers table
            `CREATE TABLE IF NOT EXISTS suppliers (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                name VARCHAR(255) NOT NULL,
                type VARCHAR(100),
                contact_person VARCHAR(255),
                email VARCHAR(255),
                phone VARCHAR(50),
                address TEXT,
                products_count INTEGER DEFAULT 0,
                rating DECIMAL(2,1),
                status VARCHAR(50) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Products table
            `CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100),
                unit VARCHAR(50),
                price DECIMAL(10,2),
                stock INTEGER DEFAULT 0,
                min_stock INTEGER DEFAULT 0,
                max_stock INTEGER DEFAULT 1000,
                supplier_id INTEGER REFERENCES suppliers(id),
                storage_location VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Recipes table
            `CREATE TABLE IF NOT EXISTS recipes (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                name VARCHAR(255) NOT NULL,
                category VARCHAR(50),
                portions INTEGER,
                prep_time INTEGER,
                cook_time INTEGER,
                cost_per_portion DECIMAL(10,2),
                instructions TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Recipe ingredients
            `CREATE TABLE IF NOT EXISTS recipe_ingredients (
                id SERIAL PRIMARY KEY,
                recipe_id INTEGER REFERENCES recipes(id) ON DELETE CASCADE,
                product_id INTEGER REFERENCES products(id),
                quantity DECIMAL(10,2),
                unit VARCHAR(50)
            )`,
            
            // Orders table
            `CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                supplier_id INTEGER REFERENCES suppliers(id),
                order_date DATE,
                delivery_date DATE,
                status VARCHAR(50),
                total_amount DECIMAL(10,2),
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Order items
            `CREATE TABLE IF NOT EXISTS order_items (
                id SERIAL PRIMARY KEY,
                order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
                product_id INTEGER REFERENCES products(id),
                quantity DECIMAL(10,2),
                unit_price DECIMAL(10,2),
                total_price DECIMAL(10,2)
            )`,
            
            // Inventory
            `CREATE TABLE IF NOT EXISTS inventory (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                product_id INTEGER REFERENCES products(id),
                quantity DECIMAL(10,2),
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )`,
            
            // Meal plans
            `CREATE TABLE IF NOT EXISTS meal_plans (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                week_number INTEGER,
                year INTEGER,
                day_of_week VARCHAR(20),
                meal_type VARCHAR(20),
                recipe_id INTEGER REFERENCES recipes(id),
                servings INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            
            // Create indexes
            `CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id)`,
            `CREATE INDEX IF NOT EXISTS idx_recipes_tenant ON recipes(tenant_id)`,
            `CREATE INDEX IF NOT EXISTS idx_suppliers_tenant ON suppliers(tenant_id)`,
            `CREATE INDEX IF NOT EXISTS idx_orders_tenant ON orders(tenant_id)`,
            `CREATE INDEX IF NOT EXISTS idx_meal_plans_week ON meal_plans(tenant_id, week_number, year)`
        ];
        
        for (const query of queries) {
            try {
                await pool.query(query);
            } catch (error) {
                console.error('Error creating table:', error.message);
            }
        }
        
        console.log('✅ All tables created successfully');
    }
};