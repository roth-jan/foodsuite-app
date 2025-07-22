const db = require('../database/db-simple');

async function seedDatabase() {
    try {
        console.log('🌱 Seeding FoodSuite database...');
        
        await db.initialize();
        
        // Get demo tenant
        const tenant = await db.get(
            'SELECT * FROM tenants WHERE tenant_key = ?', 
            ['demo']
        );
        
        if (!tenant) {
            throw new Error('Demo tenant not found. Please run init-database first.');
        }
        
        const tenantId = tenant.id;
        
        // Clear existing data
        await db.run('DELETE FROM meal_plans WHERE tenant_id = ?', [tenantId]);
        await db.run('DELETE FROM recipe_ingredients WHERE recipe_id IN (SELECT id FROM recipes WHERE tenant_id = ?)', [tenantId]);
        await db.run('DELETE FROM recipes WHERE tenant_id = ?', [tenantId]);
        await db.run('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE tenant_id = ?)', [tenantId]);
        await db.run('DELETE FROM orders WHERE tenant_id = ?', [tenantId]);
        await db.run('DELETE FROM products WHERE tenant_id = ?', [tenantId]);
        await db.run('DELETE FROM suppliers WHERE tenant_id = ?', [tenantId]);
        
        // Seed suppliers
        const suppliers = [
            {
                tenant_id: tenantId,
                name: 'Metro AG',
                type: 'Großhändler',
                contact_person: 'Max Mustermann',
                email: 'kontakt@metro.de',
                phone: '+49 123 456789',
                address: 'Industriestraße 1, 12345 Berlin',
                products_count: 25,
                rating: 4.2,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                name: 'Bio-Hof Müller',
                type: 'Bio-Lieferant',
                contact_person: 'Anna Müller',
                email: 'info@bio-mueller.de',
                phone: '+49 987 654321',
                address: 'Hofstraße 5, 54321 Landstadt',
                products_count: 15,
                rating: 4.8,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                name: 'Frische Früchte GmbH',
                type: 'Obst & Gemüse',
                contact_person: 'Peter Schmidt',
                email: 'service@frische-fruechte.com',
                phone: '+49 555 123456',
                address: 'Marktplatz 3, 67890 Gemüsehausen',
                products_count: 30,
                rating: 4.5,
                status: 'active'
            }
        ];
        
        const supplierIds = [];
        for (const supplier of suppliers) {
            const result = await db.create('suppliers', supplier);
            supplierIds.push(result.id);
        }
        
        // Get category IDs
        const meatCategory = await db.get('SELECT id FROM product_categories WHERE code = ?', ['meat']);
        const vegetablesCategory = await db.get('SELECT id FROM product_categories WHERE code = ?', ['vegetables']);
        const dairyCategory = await db.get('SELECT id FROM product_categories WHERE code = ?', ['dairy']);
        const grainCategory = await db.get('SELECT id FROM product_categories WHERE code = ?', ['grains']);
        const spicesCategory = await db.get('SELECT id FROM product_categories WHERE code = ?', ['spices']);
        
        // Seed products
        const products = [
            {
                tenant_id: tenantId,
                article_number: 'ART-001',
                name: 'Rindfleisch 1kg',
                category_id: meatCategory.id,
                supplier_id: supplierIds[0],
                price: 12.50,
                stock: 45,
                min_stock: 20,
                unit: 'kg',
                storage_location: 'Kühlraum A',
                shelf_life_days: 3,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                article_number: 'ART-002',
                name: 'Karotten Bio 1kg',
                category_id: vegetablesCategory.id,
                supplier_id: supplierIds[1],
                price: 2.80,
                stock: 25,
                min_stock: 15,
                unit: 'kg',
                storage_location: 'Kühlraum B',
                shelf_life_days: 7,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                article_number: 'ART-003',
                name: 'Tomaten 1kg',
                category_id: vegetablesCategory.id,
                supplier_id: supplierIds[2],
                price: 3.20,
                stock: 8,
                min_stock: 25,
                unit: 'kg',
                storage_location: 'Kühlraum B',
                shelf_life_days: 5,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                article_number: 'ART-004',
                name: 'Vollmilch 1L',
                category_id: dairyCategory.id,
                supplier_id: supplierIds[0],
                price: 1.20,
                stock: 50,
                min_stock: 20,
                unit: 'L',
                storage_location: 'Kühlraum C',
                shelf_life_days: 4,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                article_number: 'ART-005',
                name: 'Nudeln 500g',
                category_id: grainCategory.id,
                supplier_id: supplierIds[0],
                price: 1.50,
                stock: 100,
                min_stock: 30,
                unit: 'pkg',
                storage_location: 'Trockenlager',
                shelf_life_days: 365,
                status: 'active'
            },
            {
                tenant_id: tenantId,
                article_number: 'ART-006',
                name: 'Olivenöl 1L',
                category_id: spicesCategory.id,
                supplier_id: supplierIds[1],
                price: 8.50,
                stock: 12,
                min_stock: 5,
                unit: 'L',
                storage_location: 'Trockenlager',
                shelf_life_days: 730,
                status: 'active'
            }
        ];
        
        const productIds = [];
        for (const product of products) {
            const result = await db.create('products', product);
            productIds.push(result.id);
        }
        
        // Get recipe category IDs
        const mainCategory = await db.get('SELECT id FROM recipe_categories WHERE code = ?', ['main']);
        const soupCategory = await db.get('SELECT id FROM recipe_categories WHERE code = ?', ['soup']);
        
        // Seed recipes
        const recipes = [
            {
                tenant_id: tenantId,
                name: 'Rindergulasch',
                category_id: mainCategory.id,
                cost_per_portion: 4.50,
                portions: 6,
                prep_time: 20,
                cook_time: 120,
                calories_per_portion: 420,
                protein_per_portion: 35.0,
                carbs_per_portion: 15.0,
                fat_per_portion: 25.0,
                instructions: '1. Rindfleisch in Würfel schneiden\n2. Zwiebeln anbraten\n3. Fleisch hinzufügen und anbraten\n4. Mit Brühe ablöschen\n5. 2 Stunden köcheln lassen',
                tags: 'protein,hearty,comfort-food',
                status: 'active'
            },
            {
                tenant_id: tenantId,
                name: 'Gemüsesuppe',
                category_id: soupCategory.id,
                cost_per_portion: 2.80,
                portions: 4,
                prep_time: 15,
                cook_time: 30,
                calories_per_portion: 150,
                protein_per_portion: 8.0,
                carbs_per_portion: 20.0,
                fat_per_portion: 5.0,
                instructions: '1. Gemüse waschen und schneiden\n2. In Brühe kochen\n3. Würzen und servieren',
                tags: 'vegetarian,healthy,light',
                status: 'active'
            },
            {
                tenant_id: tenantId,
                name: 'Nudeln mit Tomatensauce',
                category_id: mainCategory.id,
                cost_per_portion: 3.20,
                portions: 4,
                prep_time: 10,
                cook_time: 20,
                calories_per_portion: 380,
                protein_per_portion: 12.0,
                carbs_per_portion: 65.0,
                fat_per_portion: 8.0,
                instructions: '1. Nudeln kochen\n2. Tomaten für Sauce verarbeiten\n3. Würzen und servieren',
                tags: 'vegetarian,pasta,quick',
                status: 'active'
            }
        ];
        
        const recipeIds = [];
        for (const recipe of recipes) {
            const result = await db.create('recipes', recipe);
            recipeIds.push(result.id);
        }
        
        // Seed recipe ingredients
        const recipeIngredients = [
            // Rindergulasch
            { recipe_id: recipeIds[0], product_id: productIds[0], quantity: 1.0, unit: 'kg' },
            { recipe_id: recipeIds[0], product_id: productIds[1], quantity: 0.5, unit: 'kg' },
            { recipe_id: recipeIds[0], product_id: productIds[5], quantity: 0.1, unit: 'L' },
            
            // Gemüsesuppe
            { recipe_id: recipeIds[1], product_id: productIds[1], quantity: 0.3, unit: 'kg' },
            { recipe_id: recipeIds[1], product_id: productIds[2], quantity: 0.2, unit: 'kg' },
            
            // Nudeln mit Tomatensauce
            { recipe_id: recipeIds[2], product_id: productIds[4], quantity: 2.0, unit: 'pkg' },
            { recipe_id: recipeIds[2], product_id: productIds[2], quantity: 0.6, unit: 'kg' },
            { recipe_id: recipeIds[2], product_id: productIds[5], quantity: 0.05, unit: 'L' }
        ];
        
        for (const ingredient of recipeIngredients) {
            await db.create('recipe_ingredients', ingredient);
        }
        
        // Seed orders
        const orders = [
            {
                tenant_id: tenantId,
                order_number: 'ORD-2024-001',
                supplier_id: supplierIds[0],
                order_date: '2024-01-15',
                delivery_date: '2024-01-16',
                status: 'pending',
                total_amount: 245.80,
                delivery_address: 'Hauptküche, Musterstraße 123, 12345 Musterstadt'
            },
            {
                tenant_id: tenantId,
                order_number: 'ORD-2024-002',
                supplier_id: supplierIds[1],
                order_date: '2024-01-14',
                delivery_date: '2024-01-15',
                status: 'delivered',
                total_amount: 156.40,
                delivery_address: 'Hauptküche, Musterstraße 123, 12345 Musterstadt'
            }
        ];
        
        const orderIds = [];
        for (const order of orders) {
            const result = await db.create('orders', order);
            orderIds.push(result.id);
        }
        
        // Seed order items
        const orderItems = [
            // Order 1
            { order_id: orderIds[0], product_id: productIds[0], quantity: 10, unit_price: 12.50, total_price: 125.00 },
            { order_id: orderIds[0], product_id: productIds[3], quantity: 20, unit_price: 1.20, total_price: 24.00 },
            { order_id: orderIds[0], product_id: productIds[4], quantity: 64, unit_price: 1.50, total_price: 96.00 },
            
            // Order 2
            { order_id: orderIds[1], product_id: productIds[1], quantity: 30, unit_price: 2.80, total_price: 84.00 },
            { order_id: orderIds[1], product_id: productIds[5], quantity: 8, unit_price: 8.50, total_price: 68.00 }
        ];
        
        for (const item of orderItems) {
            await db.create('order_items', item);
        }
        
        // Seed meal plans (current week)
        const currentWeek = 3;
        const currentYear = 2024;
        
        const mealPlans = [
            // Monday
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 1, meal_type: 'lunch', recipe_id: recipeIds[0], planned_portions: 50 },
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 1, meal_type: 'dinner', recipe_id: recipeIds[2], planned_portions: 40 },
            
            // Tuesday
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 2, meal_type: 'lunch', recipe_id: recipeIds[1], planned_portions: 45 },
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 2, meal_type: 'dinner', recipe_id: recipeIds[0], planned_portions: 35 },
            
            // Wednesday
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 3, meal_type: 'lunch', recipe_id: recipeIds[2], planned_portions: 55 },
            { tenant_id: tenantId, week_number: currentWeek, year: currentYear, day_of_week: 3, meal_type: 'dinner', recipe_id: recipeIds[1], planned_portions: 30 }
        ];
        
        for (const mealPlan of mealPlans) {
            await db.create('meal_plans', mealPlan);
        }
        
        // Seed some inventory transactions
        const transactions = [
            {
                tenant_id: tenantId,
                product_id: productIds[0],
                transaction_type: 'in',
                quantity: 20,
                unit_cost: 12.50,
                total_cost: 250.00,
                reference_type: 'order',
                reference_id: orderIds[0],
                notes: 'Lieferung von Metro AG'
            },
            {
                tenant_id: tenantId,
                product_id: productIds[1],
                transaction_type: 'in',
                quantity: 30,
                unit_cost: 2.80,
                total_cost: 84.00,
                reference_type: 'order',
                reference_id: orderIds[1],
                notes: 'Bio-Lieferung von Hof Müller'
            },
            {
                tenant_id: tenantId,
                product_id: productIds[0],
                transaction_type: 'out',
                quantity: 5,
                unit_cost: 12.50,
                total_cost: 62.50,
                reference_type: 'meal_plan',
                reference_id: 1,
                notes: 'Verbrauch für Rindergulasch'
            }
        ];
        
        for (const transaction of transactions) {
            await db.create('inventory_transactions', transaction);
        }
        
        console.log('✅ Database seeded successfully!');
        console.log(`📊 Created:`);
        console.log(`   - ${suppliers.length} suppliers`);
        console.log(`   - ${products.length} products`);
        console.log(`   - ${recipes.length} recipes`);
        console.log(`   - ${recipeIngredients.length} recipe ingredients`);
        console.log(`   - ${orders.length} orders`);
        console.log(`   - ${orderItems.length} order items`);
        console.log(`   - ${mealPlans.length} meal plans`);
        console.log(`   - ${transactions.length} inventory transactions`);
        
        await db.close();
        process.exit(0);
        
    } catch (error) {
        console.error('❌ Database seeding failed:', error);
        process.exit(1);
    }
}

seedDatabase();