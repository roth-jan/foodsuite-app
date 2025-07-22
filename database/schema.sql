-- FoodSuite Database Schema
-- SQLite compatible schema for local development

-- Users/Tenants table
CREATE TABLE tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_key VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    current_week INTEGER DEFAULT 1,
    ai_mode VARCHAR(20) DEFAULT 'cost',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Suppliers table
CREATE TABLE suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100),
    contact_person VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    products_count INTEGER DEFAULT 0,
    rating DECIMAL(3,2) DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Product categories
CREATE TABLE product_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    article_number VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category_id INTEGER,
    supplier_id INTEGER,
    price DECIMAL(10,2) NOT NULL,
    stock INTEGER DEFAULT 0,
    min_stock INTEGER DEFAULT 0,
    max_stock INTEGER DEFAULT 1000,
    unit VARCHAR(20) DEFAULT 'kg',
    storage_location VARCHAR(100),
    shelf_life_days INTEGER DEFAULT 7,
    description TEXT,
    allergens TEXT,
    nutritional_info TEXT,
    status VARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES product_categories(id),
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
);

-- Recipe categories
CREATE TABLE recipe_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Recipes table
CREATE TABLE recipes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    category_id INTEGER,
    cost_per_portion DECIMAL(10,2) DEFAULT 0.0,
    portions INTEGER DEFAULT 4,
    prep_time INTEGER DEFAULT 30,
    cook_time INTEGER DEFAULT 30,
    calories_per_portion INTEGER DEFAULT 0,
    protein_per_portion DECIMAL(5,2) DEFAULT 0.0,
    carbs_per_portion DECIMAL(5,2) DEFAULT 0.0,
    fat_per_portion DECIMAL(5,2) DEFAULT 0.0,
    instructions TEXT,
    notes TEXT,
    tags TEXT,
    image_url VARCHAR(500),
    status VARCHAR(20) DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES recipe_categories(id)
);

-- Recipe ingredients (junction table)
CREATE TABLE recipe_ingredients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipe_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity DECIMAL(10,3) NOT NULL,
    unit VARCHAR(20) NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (recipe_id) REFERENCES recipes(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Orders table
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    order_number VARCHAR(50) UNIQUE NOT NULL,
    supplier_id INTEGER NOT NULL,
    order_date DATE NOT NULL,
    delivery_date DATE,
    status VARCHAR(20) DEFAULT 'pending',
    total_amount DECIMAL(10,2) DEFAULT 0.0,
    notes TEXT,
    delivery_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
);

-- Order items table
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    total_price DECIMAL(10,2) NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Meal plans table
CREATE TABLE meal_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    week_number INTEGER NOT NULL,
    year INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL, -- 1=Monday, 7=Sunday
    meal_type VARCHAR(20) NOT NULL, -- breakfast, lunch, dinner
    recipe_id INTEGER,
    planned_portions INTEGER DEFAULT 1,
    actual_portions INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (recipe_id) REFERENCES recipes(id),
    UNIQUE(tenant_id, week_number, year, day_of_week, meal_type)
);

-- Inventory transactions table
CREATE TABLE inventory_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    transaction_type VARCHAR(20) NOT NULL, -- 'in', 'out', 'adjustment', 'transfer'
    quantity INTEGER NOT NULL,
    unit_cost DECIMAL(10,2),
    total_cost DECIMAL(10,2),
    reference_type VARCHAR(20), -- 'order', 'meal_plan', 'manual'
    reference_id INTEGER,
    notes TEXT,
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Settings table for tenant-specific configuration
CREATE TABLE tenant_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    setting_key VARCHAR(100) NOT NULL,
    setting_value TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(tenant_id, setting_key)
);

-- Indexes for performance
CREATE INDEX idx_products_tenant ON products(tenant_id);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_products_supplier ON products(supplier_id);
CREATE INDEX idx_products_article ON products(article_number);

CREATE INDEX idx_recipes_tenant ON recipes(tenant_id);
CREATE INDEX idx_recipes_category ON recipes(category_id);

CREATE INDEX idx_orders_tenant ON orders(tenant_id);
CREATE INDEX idx_orders_supplier ON orders(supplier_id);
CREATE INDEX idx_orders_date ON orders(order_date);

CREATE INDEX idx_meal_plans_tenant ON meal_plans(tenant_id);
CREATE INDEX idx_meal_plans_week ON meal_plans(week_number, year);

CREATE INDEX idx_inventory_tenant ON inventory_transactions(tenant_id);
CREATE INDEX idx_inventory_product ON inventory_transactions(product_id);
CREATE INDEX idx_inventory_date ON inventory_transactions(created_at);

-- Insert default categories
INSERT INTO product_categories (name, code, description) VALUES
('Fleisch', 'meat', 'Fleisch und Fleischprodukte'),
('Gemüse', 'vegetables', 'Frisches Gemüse und Kräuter'),
('Milchprodukte', 'dairy', 'Milch, Käse, Joghurt und andere Milchprodukte'),
('Getränke', 'beverages', 'Getränke aller Art'),
('Backwaren', 'bakery', 'Brot, Brötchen und Backwaren'),
('Gewürze', 'spices', 'Gewürze und Aromaten'),
('Getreide', 'grains', 'Reis, Nudeln, Mehl und Getreideprodukte'),
('Tiefkühlkost', 'frozen', 'Tiefgekühlte Produkte'),
('Konserven', 'canned', 'Konserven und haltbare Produkte'),
('Süßwaren', 'sweets', 'Süßigkeiten und Desserts');

INSERT INTO recipe_categories (name, code, description) VALUES
('Frühstück', 'breakfast', 'Frühstücksgerichte'),
('Vorspeise', 'appetizer', 'Vorspeisen und Snacks'),
('Hauptspeise', 'main', 'Hauptgerichte'),
('Beilage', 'side', 'Beilagen'),
('Nachspeise', 'dessert', 'Desserts und Süßspeisen'),
('Suppe', 'soup', 'Suppen und Eintöpfe'),
('Salat', 'salad', 'Salate'),
('Getränk', 'beverage', 'Getränke');