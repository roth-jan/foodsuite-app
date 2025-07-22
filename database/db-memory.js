// In-Memory Database for FoodSuite with extensive canteen test data
const canteenTestData = require('./canteen-test-data');
const userManagement = require('./user-management');
const { authSchema, systemRoles, systemPermissions, defaultRolePermissions } = require('./auth-schema');

class InMemoryDatabase {
    constructor() {
        this.data = {
            tenants: [],
            users: [],
            user_sessions: [],
            roles: [],
            permissions: [],
            role_permissions: [],
            audit_log: [],
            password_resets: [],
            suppliers: [],
            products: [],
            product_categories: [],
            recipe_categories: [],
            recipes: [],
            recipe_ingredients: [],
            orders: [],
            order_items: [],
            meal_plans: [],
            meal_plan_approvals: [],
            inventory_transactions: [],
            automation_settings: [],
            shopping_lists: [],
            shopping_list_items: [],
            order_suggestions: [],
            goods_receipts: [],
            goods_receipt_items: [],
            user_roles: userManagement.userRoles,
            approval_states: userManagement.approvalStates
        };
        this.nextId = 1000; // Start with higher ID for new records
    }

    async initialize() {
        console.log('📊 Initializing in-memory database with canteen test data');
        await this.seedInitialData();
        return Promise.resolve();
    }

    async seedInitialData() {
        // Seed product categories
        this.data.product_categories = [
            { id: 1, name: 'Fleisch', code: 'meat', description: 'Fleisch und Fleischprodukte' },
            { id: 2, name: 'Gemüse', code: 'vegetables', description: 'Frisches Gemüse und Kräuter' },
            { id: 3, name: 'Molkereiprodukte', code: 'dairy', description: 'Milch, Käse, Joghurt' },
            { id: 4, name: 'Getränke', code: 'beverages', description: 'Getränke aller Art' },
            { id: 5, name: 'Backwaren', code: 'bakery', description: 'Brot, Brötchen und Backwaren' },
            { id: 6, name: 'Gewürze', code: 'spices', description: 'Gewürze und Aromaten' },
            { id: 7, name: 'Grundnahrung', code: 'grains', description: 'Reis, Nudeln, Mehl' },
            { id: 8, name: 'Tiefkühl', code: 'frozen', description: 'Tiefkühlprodukte' },
            { id: 9, name: 'Konserven', code: 'canned', description: 'Konserven und Gläser' },
            { id: 10, name: 'Öle/Fette', code: 'oils', description: 'Öle und Fette' }
        ];

        // Seed recipe categories
        this.data.recipe_categories = [
            { id: 1, name: 'Frühstück', code: 'breakfast', description: 'Frühstücksgerichte' },
            { id: 2, name: 'Vorspeise', code: 'appetizer', description: 'Vorspeisen und Snacks' },
            { id: 3, name: 'Hauptgericht', code: 'main', description: 'Hauptgerichte' },
            { id: 4, name: 'Beilage', code: 'side', description: 'Beilagen' },
            { id: 5, name: 'Dessert', code: 'dessert', description: 'Desserts' },
            { id: 6, name: 'Suppe', code: 'soup', description: 'Suppen und Eintöpfe' },
            { id: 7, name: 'Salat', code: 'salad', description: 'Salate' },
            { id: 8, name: 'Eintopf', code: 'stew', description: 'Eintöpfe' },
            { id: 9, name: 'Special', code: 'special', description: 'Spezialgerichte' }
        ];

        // Seed tenants for canteen/catering
        this.data.tenants = [
            {
                id: 1,
                tenant_key: 'demo',
                name: 'Kantine Hauptwerk',
                email: 'info@kantine-hauptwerk.de',
                phone: '+49 89 123456',
                address: 'Werksstraße 15, 80339 München',
                current_week: 3,
                ai_mode: 'cost',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 2,
                tenant_key: 'mensa',
                name: 'Uni Mensa Campus',
                email: 'verwaltung@uni-mensa.de',
                phone: '+49 89 289-13000',
                address: 'Arcisstraße 21, 80333 München',
                current_week: 3,
                ai_mode: 'balanced',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 3,
                tenant_key: 'catering',
                name: 'Catering Service Plus',
                email: 'kontakt@catering-plus.de',
                phone: '+49 89 456789',
                address: 'Landsberger Straße 234, 80687 München',
                current_week: 3,
                ai_mode: 'quality',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        ];

        // Load extensive test data from canteen-test-data.js
        this.data.suppliers = canteenTestData.suppliers;
        this.data.products = canteenTestData.products;
        this.data.recipes = canteenTestData.recipes;
        
        // Fix recipe costs for AI mode differentiation
        this.fixRecipeCosts();
        
        // Initialize authentication data
        await this.initializeAuthData();
        
        // Load user management data (will be replaced with auth users)
        // this.data.users = userManagement.users;

        // Seed orders with canteen-appropriate data
        this.data.orders = [
            {
                id: 1,
                tenant_id: 1,
                order_number: 'BES-2025-001',
                supplier_id: 1,
                order_date: new Date().toISOString(),
                delivery_date: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
                status: 'pending',
                total_amount: 2456.80,
                notes: 'Wochenbestellung KW04',
                delivery_address: 'Warenannahme, Werksstraße 15, 80339 München',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 2,
                tenant_id: 1,
                order_number: 'BES-2025-002',
                supplier_id: 2,
                order_date: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
                delivery_date: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString(),
                status: 'confirmed',
                total_amount: 3189.50,
                notes: 'Großbestellung Grundnahrungsmittel',
                delivery_address: 'Warenannahme, Werksstraße 15, 80339 München',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            },
            {
                id: 3,
                tenant_id: 1,
                order_number: 'BES-2025-003',
                supplier_id: 4,
                order_date: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
                delivery_date: new Date().toISOString(),
                status: 'delivered',
                total_amount: 1856.00,
                notes: 'Fleischbestellung für KW03',
                delivery_address: 'Warenannahme, Werksstraße 15, 80339 München',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        ];

        // Seed order items
        this.data.order_items = [
            { id: 1, order_id: 1, product_id: 1, quantity: 100, unit_price: 18.50, total_price: 1850.00, notes: '', created_at: new Date().toISOString() },
            { id: 2, order_id: 1, product_id: 3, quantity: 50, unit_price: 22.90, total_price: 1145.00, notes: '', created_at: new Date().toISOString() },
            { id: 3, order_id: 1, product_id: 5, quantity: 80, unit_price: 11.50, total_price: 920.00, notes: '', created_at: new Date().toISOString() },
            { id: 4, order_id: 2, product_id: 21, quantity: 60, unit_price: 54.50, total_price: 3270.00, notes: '', created_at: new Date().toISOString() },
            { id: 5, order_id: 2, product_id: 23, quantity: 80, unit_price: 48.90, total_price: 3912.00, notes: '', created_at: new Date().toISOString() }
        ];

        // Generate more orders for today and recent days
        const today = new Date();
        for (let i = 0; i < 7; i++) {
            const orderDate = new Date(today);
            orderDate.setDate(orderDate.getDate() - i);
            
            this.data.orders.push({
                id: 4 + i,
                tenant_id: 1,
                order_number: `BES-2025-${String(4 + i).padStart(3, '0')}`,
                supplier_id: (i % 4) + 1,
                order_date: orderDate.toISOString(),
                delivery_date: new Date(orderDate.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString(),
                status: i < 2 ? 'delivered' : i < 4 ? 'confirmed' : 'pending',
                total_amount: 1500 + Math.random() * 2000,
                notes: `Bestellung KW${Math.floor((orderDate.getDate() - 1) / 7) + 1}`,
                delivery_address: 'Warenannahme, Werksstraße 15, 80339 München',
                created_at: orderDate.toISOString(),
                updated_at: orderDate.toISOString()
            });
        }

        // Seed meal plans with canteen-appropriate portions
        this.data.meal_plans = [
            { id: 1, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 1, meal_type: 'lunch', recipe_id: 1, planned_portions: 500, actual_portions: 0, notes: '', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            { id: 2, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 1, meal_type: 'lunch', recipe_id: 9, planned_portions: 350, actual_portions: 0, notes: 'Vegetarische Option', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            { id: 3, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 2, meal_type: 'lunch', recipe_id: 4, planned_portions: 450, actual_portions: 0, notes: '', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            { id: 4, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 2, meal_type: 'lunch', recipe_id: 14, planned_portions: 400, actual_portions: 0, notes: 'Vegane Option', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            { id: 5, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 3, meal_type: 'lunch', recipe_id: 19, planned_portions: 600, actual_portions: 0, notes: '', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
            { id: 6, tenant_id: 1, week_number: 3, year: 2025, day_of_week: 3, meal_type: 'lunch', recipe_id: 15, planned_portions: 300, actual_portions: 0, notes: 'Vegane Option', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
        ];

        // Seed recipe ingredients (linking recipes to products)
        this.data.recipe_ingredients = [
            { id: 1, recipe_id: 1, product_id: 21, quantity: 50.0, unit: 'kg', notes: 'Rindergulasch', created_at: new Date().toISOString() },
            { id: 2, recipe_id: 1, product_id: 1, quantity: 25.0, unit: 'kg', notes: 'Kartoffeln', created_at: new Date().toISOString() },
            { id: 3, recipe_id: 1, product_id: 38, quantity: 10.0, unit: 'kg', notes: 'Zwiebeln', created_at: new Date().toISOString() },
            { id: 4, recipe_id: 1, product_id: 47, quantity: 0.5, unit: 'kg', notes: 'Pfeffer', created_at: new Date().toISOString() },
            { id: 5, recipe_id: 1, product_id: 48, quantity: 0.8, unit: 'kg', notes: 'Paprika', created_at: new Date().toISOString() },
            
            { id: 6, recipe_id: 4, product_id: 23, quantity: 45.0, unit: 'kg', notes: 'Hähnchenbrust', created_at: new Date().toISOString() },
            { id: 7, recipe_id: 4, product_id: 3, quantity: 20.0, unit: 'kg', notes: 'Reis', created_at: new Date().toISOString() },
            { id: 8, recipe_id: 4, product_id: 49, quantity: 1.0, unit: 'kg', notes: 'Curry', created_at: new Date().toISOString() },
            { id: 9, recipe_id: 4, product_id: 97, quantity: 10.0, unit: 'L', notes: 'Kokosmilch', created_at: new Date().toISOString() },
            
            { id: 10, recipe_id: 9, product_id: 43, quantity: 20.0, unit: 'kg', notes: 'Tomaten', created_at: new Date().toISOString() },
            { id: 11, recipe_id: 9, product_id: 39, quantity: 15.0, unit: 'kg', notes: 'Möhren', created_at: new Date().toISOString() },
            { id: 12, recipe_id: 9, product_id: 42, quantity: 10.0, unit: 'kg', notes: 'Paprika', created_at: new Date().toISOString() },
            { id: 13, recipe_id: 9, product_id: 135, quantity: 5.0, unit: 'kg', notes: 'Lasagneplatten', created_at: new Date().toISOString() },
            { id: 14, recipe_id: 9, product_id: 32, quantity: 8.0, unit: 'kg', notes: 'Käse', created_at: new Date().toISOString() }
        ];

        // Generate inventory transactions
        this.data.inventory_transactions = [];
        const transactionTypes = ['in', 'out', 'adjustment'];
        
        // Generate 30 transactions for the last 14 days
        for (let i = 0; i < 30; i++) {
            const daysAgo = Math.floor(Math.random() * 14);
            const transDate = new Date();
            transDate.setDate(transDate.getDate() - daysAgo);
            
            const product = this.data.products[Math.floor(Math.random() * Math.min(50, this.data.products.length))];
            const type = transactionTypes[Math.floor(Math.random() * transactionTypes.length)];
            const quantity = type === 'out' ? -(10 + Math.floor(Math.random() * 50)) : (20 + Math.floor(Math.random() * 100));
            
            this.data.inventory_transactions.push({
                id: 1000 + i,
                tenant_id: 1,
                product_id: product.id,
                type: type,
                quantity: quantity,
                unit_cost: product.price,
                total_cost: Math.abs(quantity * product.price),
                reference_type: type === 'in' ? 'order' : type === 'out' ? 'recipe' : 'manual',
                reference_id: type === 'in' ? this.data.orders[Math.floor(Math.random() * 3)].id : null,
                notes: type === 'adjustment' ? 'Inventur-Anpassung' : type === 'out' ? 'Verbrauch für Speiseplan' : 'Wareneingang',
                created_at: transDate.toISOString(),
                updated_at: transDate.toISOString()
            });
        }

        // Initialize empty price monitoring data
        this.data.price_alerts = [];
        this.data.price_history = [];

        console.log('✅ Canteen test data loaded successfully');
        console.log(`📊 Loaded: ${this.data.products.length} products, ${this.data.recipes.length} recipes, ${this.data.suppliers.length} suppliers`);
        console.log(`📦 Generated: ${this.data.orders.length} orders, ${this.data.inventory_transactions.length} inventory transactions`);
    }

    // Generic SQL query method (for compatibility)
    rawQuery(sql, params = []) {
        // This is a very basic SQL parser for demo purposes
        // In a real application, you would use a proper SQL parser
        
        const lowerSql = sql.toLowerCase().trim();
        
        if (lowerSql.startsWith('select')) {
            return this.handleSelect(sql, params);
        } else if (lowerSql.startsWith('insert')) {
            return this.handleInsert(sql, params);
        } else if (lowerSql.startsWith('update')) {
            return this.handleUpdate(sql, params);
        } else if (lowerSql.startsWith('delete')) {
            return this.handleDelete(sql, params);
        } else {
            return Promise.resolve([]);
        }
    }

    handleSelect(sql, params) {
        // Very basic SELECT handling for demo
        const results = [];
        
        // Extract table name
        const tableMatch = sql.match(/from\s+(\w+)/i);
        if (!tableMatch) return Promise.resolve(results);
        
        const tableName = tableMatch[1];
        const tableData = this.data[tableName] || [];
        
        // Simple WHERE clause handling
        if (sql.includes('WHERE')) {
            // For demo, we'll handle some basic cases
            if (sql.includes('tenant_key = ?')) {
                const tenantKey = params[0];
                const result = tableData.find(row => row.tenant_key === tenantKey);
                return Promise.resolve(result || null);
            }
            
            if (sql.includes('id = ?')) {
                const id = params[0];
                const result = tableData.find(row => row.id == id);
                return Promise.resolve(result || null);
            }
            
            if (sql.includes('COUNT(*)')) {
                return Promise.resolve({ count: tableData.length });
            }
        }
        
        return Promise.resolve(tableData);
    }

    handleInsert(sql, params) {
        // Basic INSERT handling
        const tableMatch = sql.match(/insert\s+into\s+(\w+)/i);
        if (!tableMatch) return Promise.resolve({ lastID: 0, changes: 0 });
        
        const tableName = tableMatch[1];
        const newId = this.nextId++;
        
        // Extract column names
        const columnsMatch = sql.match(/\(([^)]+)\)/);
        if (!columnsMatch) return Promise.resolve({ lastID: 0, changes: 0 });
        
        const columns = columnsMatch[1].split(',').map(col => col.trim());
        
        // Create new record
        const newRecord = { id: newId };
        columns.forEach((col, index) => {
            newRecord[col] = params[index];
        });
        
        // Add timestamps
        newRecord.created_at = new Date().toISOString();
        newRecord.updated_at = new Date().toISOString();
        
        // Add to table
        if (!this.data[tableName]) this.data[tableName] = [];
        this.data[tableName].push(newRecord);
        
        return Promise.resolve({ lastID: newId, changes: 1 });
    }

    handleUpdate(sql, params) {
        // Basic UPDATE handling
        const tableMatch = sql.match(/update\s+(\w+)/i);
        if (!tableMatch) return Promise.resolve({ changes: 0 });
        
        const tableName = tableMatch[1];
        const tableData = this.data[tableName] || [];
        
        // Find record to update
        const idMatch = sql.match(/where\s+id\s*=\s*\?/i);
        if (idMatch) {
            const id = params[params.length - 1]; // ID is usually the last parameter
            const record = tableData.find(row => row.id == id);
            if (record) {
                // Update timestamp
                record.updated_at = new Date().toISOString();
                return Promise.resolve({ changes: 1 });
            }
        }
        
        return Promise.resolve({ changes: 0 });
    }

    handleDelete(sql, params) {
        // Basic DELETE handling
        const tableMatch = sql.match(/delete\s+from\s+(\w+)/i);
        if (!tableMatch) return Promise.resolve({ changes: 0 });
        
        const tableName = tableMatch[1];
        const tableData = this.data[tableName] || [];
        
        const idMatch = sql.match(/where\s+id\s*=\s*\?/i);
        if (idMatch) {
            const id = params[0];
            const index = tableData.findIndex(row => row.id == id);
            if (index !== -1) {
                tableData.splice(index, 1);
                return Promise.resolve({ changes: 1 });
            }
        }
        
        return Promise.resolve({ changes: 0 });
    }

    // Get single row
    get(sql, params = []) {
        return this.rawQuery(sql, params).then(result => {
            if (Array.isArray(result)) {
                return result[0] || null;
            }
            return result;
        });
    }

    // Run method for INSERT, UPDATE, DELETE
    run(sql, params = []) {
        return this.rawQuery(sql, params).then(result => {
            if (result.lastID !== undefined) {
                return { lastID: result.lastID, changes: result.changes };
            }
            return { lastID: 0, changes: result.changes || 0 };
        });
    }

    // Transaction support (simplified)
    transaction(callback) {
        try {
            const result = callback(this);
            return Promise.resolve(result);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // Close database connection
    close() {
        console.log('📊 Database connection closed');
        return Promise.resolve();
    }

    // Query builder helper
    query(tableName) {
        const self = this;
        const queryObj = {
            _table: tableName,
            _conditions: [],
            _orderBy: null,
            _orderDir: 'ASC',
            _limit: null,
            _offset: null,
            _select: null,
            
            where(field, operator, value) {
                if (value === undefined) {
                    value = operator;
                    operator = '=';
                }
                this._conditions.push({ field, operator, value, type: 'AND' });
                return this;
            },
            
            orWhere(field, operator, value) {
                if (value === undefined) {
                    value = operator;
                    operator = '=';
                }
                this._conditions.push({ field, operator, value, type: 'OR' });
                return this;
            },
            
            whereIn(field, values) {
                this._conditions.push({ field, operator: 'IN', value: values, type: 'AND' });
                return this;
            },
            
            whereNot(field, value) {
                this._conditions.push({ field, operator: '!=', value, type: 'AND' });
                return this;
            },
            
            orderBy(field, direction = 'ASC') {
                this._orderBy = field;
                this._orderDir = direction.toUpperCase();
                return this;
            },
            
            limit(num) {
                this._limit = num;
                return this;
            },
            
            offset(num) {
                this._offset = num;
                return this;
            },
            
            select(fields) {
                this._select = Array.isArray(fields) ? fields : [fields];
                return this;
            },
            
            get() {
                let results = self.data[this._table] || [];
                
                // Apply conditions
                if (this._conditions.length > 0) {
                    results = results.filter(row => {
                        let match = true;
                        let lastResult = true;
                        
                        for (const condition of this._conditions) {
                            let conditionMet = false;
                            
                            switch (condition.operator) {
                                case '=':
                                    conditionMet = row[condition.field] == condition.value;
                                    break;
                                case '!=':
                                    conditionMet = row[condition.field] != condition.value;
                                    break;
                                case '>':
                                    conditionMet = row[condition.field] > condition.value;
                                    break;
                                case '<':
                                    conditionMet = row[condition.field] < condition.value;
                                    break;
                                case '>=':
                                    conditionMet = row[condition.field] >= condition.value;
                                    break;
                                case '<=':
                                    conditionMet = row[condition.field] <= condition.value;
                                    break;
                                case 'IN':
                                    conditionMet = condition.value.includes(row[condition.field]);
                                    break;
                                case 'like':
                                    const pattern = condition.value.replace(/%/g, '.*');
                                    conditionMet = new RegExp(pattern, 'i').test(row[condition.field]);
                                    break;
                            }
                            
                            if (condition.type === 'AND') {
                                match = match && conditionMet;
                            } else {
                                match = lastResult || conditionMet;
                            }
                            lastResult = conditionMet;
                        }
                        
                        return match;
                    });
                }
                
                // Apply ordering
                if (this._orderBy) {
                    results.sort((a, b) => {
                        const aVal = a[this._orderBy];
                        const bVal = b[this._orderBy];
                        
                        if (aVal < bVal) return this._orderDir === 'ASC' ? -1 : 1;
                        if (aVal > bVal) return this._orderDir === 'ASC' ? 1 : -1;
                        return 0;
                    });
                }
                
                // Apply offset and limit
                if (this._offset) {
                    results = results.slice(this._offset);
                }
                if (this._limit) {
                    results = results.slice(0, this._limit);
                }
                
                // Apply field selection
                if (this._select) {
                    results = results.map(row => {
                        const selected = {};
                        this._select.forEach(field => {
                            selected[field] = row[field];
                        });
                        return selected;
                    });
                }
                
                return results;
            },
            
            first() {
                this._limit = 1;
                const results = this.get();
                return results.length > 0 ? results[0] : null;
            },
            
            count() {
                const results = this.get();
                return results.length;
            },
            
            update(updates) {
                const results = this.get();
                results.forEach(row => {
                    const index = self.data[this._table].findIndex(r => r.id === row.id);
                    if (index !== -1) {
                        Object.assign(self.data[this._table][index], updates, {
                            updated_at: new Date().toISOString()
                        });
                    }
                });
                return results.length;
            },
            
            delete() {
                const results = this.get();
                const ids = results.map(r => r.id);
                self.data[this._table] = self.data[this._table].filter(r => !ids.includes(r.id));
                return results.length;
            }
        };
        
        return queryObj;
    }

    // Insert helper
    insert(tableName, data) {
        if (!this.data[tableName]) this.data[tableName] = [];
        
        const newId = this.nextId++;
        const newRecord = {
            id: newId,
            ...data,
            created_at: data.created_at || new Date().toISOString(),
            updated_at: data.updated_at || new Date().toISOString()
        };
        
        this.data[tableName].push(newRecord);
        return newId;
    }

    // Helper methods
    async findById(table, id, tenantId = null) {
        const tableData = this.data[table] || [];
        const record = tableData.find(row => {
            if (tenantId) {
                return row.id == id && row.tenant_id == tenantId;
            }
            return row.id == id;
        });
        return record || null;
    }

    async findAll(table, tenantId = null, options = {}) {
        let tableData = this.data[table] || [];
        
        if (tenantId) {
            tableData = tableData.filter(row => row.tenant_id == tenantId);
        }
        
        // Apply basic filtering
        if (options.where && options.params) {
            // Very basic WHERE clause handling
            // In a real implementation, you'd parse the WHERE clause properly
        }
        
        // Apply ordering
        if (options.orderBy) {
            const [column, direction] = options.orderBy.split(' ');
            tableData.sort((a, b) => {
                const aVal = a[column];
                const bVal = b[column];
                if (direction === 'DESC') {
                    return bVal > aVal ? 1 : -1;
                }
                return aVal > bVal ? 1 : -1;
            });
        }
        
        // Apply pagination
        if (options.offset) {
            tableData = tableData.slice(options.offset);
        }
        if (options.limit) {
            tableData = tableData.slice(0, options.limit);
        }
        
        return tableData;
    }

    async create(table, data) {
        const newId = this.nextId++;
        const newRecord = { 
            id: newId, 
            ...data, 
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        
        if (!this.data[table]) this.data[table] = [];
        this.data[table].push(newRecord);
        
        return newRecord;
    }

    async update(table, id, data, tenantId = null) {
        const tableData = this.data[table] || [];
        const record = tableData.find(row => {
            if (tenantId) {
                return row.id == id && row.tenant_id == tenantId;
            }
            return row.id == id;
        });
        
        if (record) {
            Object.assign(record, data);
            record.updated_at = new Date().toISOString();
            return record;
        }
        
        return null;
    }

    async delete(table, id, tenantId = null) {
        const tableData = this.data[table] || [];
        const index = tableData.findIndex(row => {
            if (tenantId) {
                return row.id == id && row.tenant_id == tenantId;
            }
            return row.id == id;
        });
        
        if (index !== -1) {
            tableData.splice(index, 1);
            return true;
        }
        
        return false;
    }

    async paginate(table, page = 1, limit = 10, tenantId = null, options = {}) {
        const offset = (page - 1) * limit;
        
        let tableData = this.data[table] || [];
        
        if (tenantId) {
            tableData = tableData.filter(row => row.tenant_id == tenantId);
        }
        
        const totalItems = tableData.length;
        const totalPages = Math.ceil(totalItems / limit);
        
        const items = await this.findAll(table, tenantId, {
            ...options,
            limit,
            offset
        });
        
        return {
            items,
            pagination: {
                page,
                limit,
                totalItems,
                totalPages,
                hasNextPage: page < totalPages,
                hasPreviousPage: page > 1
            }
        };
    }

    // Initialize authentication data
    async initializeAuthData() {
        const bcrypt = require('bcryptjs');
        
        // Add system permissions
        this.data.permissions = systemPermissions;
        
        // Add system roles
        this.data.roles = systemRoles.map(role => ({
            ...role,
            tenant_id: 'system',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }));
        
        // Add tenant-specific roles for demo tenant
        const demoRoles = systemRoles.map(role => ({
            ...role,
            id: role.id + 100,
            tenant_id: 'demo',
            is_system: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        }));
        this.data.roles.push(...demoRoles);
        
        // Add role-permission mappings
        Object.entries(defaultRolePermissions).forEach(([roleId, permissionIds]) => {
            permissionIds.forEach(permissionId => {
                // System roles
                this.data.role_permissions.push({
                    id: this.nextId++,
                    role_id: parseInt(roleId),
                    permission_id: permissionId,
                    granted_at: new Date().toISOString(),
                    granted_by: 1
                });
                // Demo tenant roles
                this.data.role_permissions.push({
                    id: this.nextId++,
                    role_id: parseInt(roleId) + 100,
                    permission_id: permissionId,
                    granted_at: new Date().toISOString(),
                    granted_by: 1
                });
            });
        });
        
        // Create default users with hashed passwords
        const defaultPassword = await bcrypt.hash('Demo123!', 10);
        
        this.data.users = [
            {
                id: 1,
                tenant_id: 'demo',
                username: 'admin',
                email: 'admin@foodsuite.de',
                password_hash: defaultPassword,
                first_name: 'Admin',
                last_name: 'User',
                role_id: 101, // Demo tenant admin role
                is_active: true,
                is_locked: false,
                failed_login_attempts: 0,
                must_change_password: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                two_factor_enabled: false,
                preferences: { theme: 'light', language: 'de' }
            },
            {
                id: 2,
                tenant_id: 'demo',
                username: 'chef',
                email: 'chef@foodsuite.de',
                password_hash: defaultPassword,
                first_name: 'Max',
                last_name: 'Musterkoch',
                role_id: 103, // Demo tenant chef role
                is_active: true,
                is_locked: false,
                failed_login_attempts: 0,
                must_change_password: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                two_factor_enabled: false,
                preferences: { theme: 'light', language: 'de' }
            },
            {
                id: 3,
                tenant_id: 'demo',
                username: 'viewer',
                email: 'viewer@foodsuite.de',
                password_hash: defaultPassword,
                first_name: 'Gast',
                last_name: 'Benutzer',
                role_id: 105, // Demo tenant viewer role
                is_active: true,
                is_locked: false,
                failed_login_attempts: 0,
                must_change_password: false,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
                two_factor_enabled: false,
                preferences: { theme: 'light', language: 'de' }
            }
        ];
    }

    // Fix recipe costs for proper AI mode differentiation
    fixRecipeCosts() {
        const RECIPE_COSTS = {
            // Breakfast items - generally cheaper
            "Rührei mit Speck": 1.85,
            "Pfannkuchen": 1.20,
            "Chia-Pudding": 2.40,
            "Französische Crepes": 2.80,
            "Avocado-Toast mit Ei": 3.20,
            "Bagel mit Lachs": 4.50,
            "Porridge mit Früchten": 1.60,
            
            // Lunch - meat dishes (expensive)
            "Hähnchenschnitzel paniert": 3.80,
            "Bratwurst mit Sauerkraut": 2.80,
            "Hackbraten mit Kartoffelpüree": 3.20,
            "Gyros mit Tzatziki und Pommes": 3.70,
            "Fischstäbchen mit Kartoffelsalat": 2.90,
            "Frikadellen mit Erbsen-Möhren": 3.30,
            "Currywurst mit Pommes": 2.60,
            "Leberkäse mit Kartoffelsalat": 2.40,
            "Maultaschen in Brühe": 2.70,
            "Quiche Lorraine": 3.40,
            "Reisfleisch": 2.80,
            "Chicken Teriyaki mit Gemüse": 3.90,
            "Königsberger Klopse": 3.90,
            
            // Lunch - vegetarian/vegan (cheaper)
            "Gemüselasagne": 2.40,
            "Gemüse-Couscous mit Kichererbsen": 1.80,
            "Gemüse-Wok mit Tofu": 2.20,
            "Gemüseauflauf": 2.10,
            "Gemüsepfanne Asiatisch": 2.00,
            "Kartoffel-Gemüse-Gratin": 1.90,
            "Kartoffelgulasch": 1.60,
            "Käsespätzle mit Röstzwiebeln": 2.30,
            "Kichererbsen-Curry": 1.70,
            "Linsencurry mit Kokosreis": 1.80,
            "Penne Arrabiata": 1.50,
            "Falafel mit Hummus": 2.10,
            "Chili sin Carne": 1.90,
            "Indisches Dal mit Naan": 1.60,
            
            // Dinner items
            "Caesar Salad mit Hähnchen": 3.20,
            "Buddha Bowl": 2.80,
            "Großer gemischter Salat": 1.40,
            "Gazpacho": 1.80,
            "Bohneneintopf mit Speck": 2.40,
            "Erbseneintopf mit Würstchen": 2.20,
            "Gulaschsuppe": 2.60,
            "Kartoffelsuppe": 1.30,
            "Kürbiscremesuppe": 1.50,
            "Linseneintopf": 1.40,
            "Nudelsalat": 1.20,
            
            // Special dishes
            "Bowl Buddha vegetarisch": 2.90,
            "Döner-Teller": 3.60,
            "Pizza Margherita (Blech)": 2.20,
            
            // Sides (very cheap)
            "Pommes frites": 0.80,
            "Reis gekocht": 0.60,
            "Salzkartoffeln": 0.70,
            "Kartoffelpüree": 0.90,
            "Gemüsereis": 1.20,
            
            // Desserts
            "Apfelstrudel": 1.60,
            "Obstsalat": 1.20,
            "Rote Grütze mit Vanillesoße": 1.40,
            "Schokoladenpudding": 0.90
        };

        console.log('🍽️ Fixing recipe costs for AI mode differentiation...');
        
        let updated = 0;
        let skipped = 0;
        
        this.data.recipes.forEach(recipe => {
            const newCost = RECIPE_COSTS[recipe.name];
            
            if (newCost) {
                const oldCost = recipe.cost_per_portion || 0;
                recipe.cost_per_portion = newCost;
                recipe.updated_at = new Date().toISOString();
                console.log(`✅ ${recipe.name}: €${oldCost} → €${newCost}`);
                updated++;
            } else {
                // Generate realistic cost based on category and tags
                const cost = this.generateRealisticCost(recipe);
                if (cost > 0) {
                    recipe.cost_per_portion = cost;
                    recipe.updated_at = new Date().toISOString();
                    console.log(`🎲 ${recipe.name}: Generated €${cost}`);
                    updated++;
                } else {
                    skipped++;
                }
            }
        });
        
        console.log(`📊 Recipe costs updated: ${updated} updated, ${skipped} skipped`);
    }
    
    generateRealisticCost(recipe) {
        const COST_RANGES = {
            breakfast: { min: 1.20, max: 2.80 },
            lunch: { min: 2.40, max: 4.50 },
            dinner: { min: 2.20, max: 4.20 },
            Dessert: { min: 0.80, max: 2.20 },
            Beilage: { min: 0.60, max: 1.80 },
            Special: { min: 2.80, max: 5.20 }
        };
        
        const TAG_MODIFIERS = {
            'Premium': 1.4,
            'Fisch': 1.3,
            'Fleisch': 1.2,
            'International': 1.1,
            'Günstig': 0.8,
            'Vegan': 0.9,
            'Vegetarisch': 0.95
        };
        
        const category = recipe.category || 'lunch';
        const range = COST_RANGES[category] || COST_RANGES.lunch;
        
        // Base cost within category range
        let baseCost = range.min + (Math.random() * (range.max - range.min));
        
        // Apply tag modifiers
        const tags = (recipe.tags || '').split(',').map(t => t.trim());
        let modifier = 1.0;
        
        tags.forEach(tag => {
            if (TAG_MODIFIERS[tag]) {
                modifier *= TAG_MODIFIERS[tag];
            }
        });
        
        // Apply portion size factor (larger portions = slightly cheaper per portion)
        const portionFactor = Math.max(0.7, 1 - (recipe.portions - 200) / 2000);
        
        return Math.round(baseCost * modifier * portionFactor * 100) / 100;
    }
}

// Create singleton instance
const database = new InMemoryDatabase();

module.exports = database;