const db = require('./postgres-client');

async function seedDatabase() {
    console.log('🌱 Starting database seeding...');
    
    try {
        // Create tables first
        await db.createTables();
        
        // Create demo tenant
        const tenantResult = await db.query(
            'INSERT INTO tenants (name) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id',
            ['demo']
        );
        
        let tenantId = 1;
        if (tenantResult.rows.length > 0) {
            tenantId = tenantResult.rows[0].id;
        } else {
            const existing = await db.query('SELECT id FROM tenants WHERE name = $1', ['demo']);
            tenantId = existing.rows[0].id;
        }
        
        console.log('✅ Demo tenant created/found:', tenantId);
        
        // Clear existing data
        await db.query('DELETE FROM meal_plans WHERE tenant_id = $1', [tenantId]);
        await db.query('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE tenant_id = $1)', [tenantId]);
        await db.query('DELETE FROM orders WHERE tenant_id = $1', [tenantId]);
        await db.query('DELETE FROM recipe_ingredients WHERE recipe_id IN (SELECT id FROM recipes WHERE tenant_id = $1)', [tenantId]);
        await db.query('DELETE FROM inventory WHERE tenant_id = $1', [tenantId]);
        await db.query('DELETE FROM recipes WHERE tenant_id = $1', [tenantId]);
        await db.query('DELETE FROM products WHERE tenant_id = $1', [tenantId]);
        await db.query('DELETE FROM suppliers WHERE tenant_id = $1', [tenantId]);
        
        // Insert suppliers
        const suppliers = [
            ['Metro Deutschland', 'Großhändler', 'Thomas Schmidt', 'bestellung@metro.de', '+49 211 6886-0', 'Schlüterstraße 3, 40235 Düsseldorf', 4.5],
            ['Transgourmet Deutschland', 'Großhändler', 'Maria Weber', 'order@transgourmet.de', '+49 69 380989-0', 'Zeilweg 16, 60439 Frankfurt', 4.7],
            ['Chefs Culinar', 'Großhändler', 'Stefan Müller', 'kundenservice@chefsculinar.de', '+49 2065 257-0', 'Holbeinstraße 18, 41460 Neuss', 4.3],
            ['EDEKA Foodservice', 'Großhändler', 'Julia Fischer', 'info@edeka-foodservice.de', '+49 40 3333-0', 'New-York-Ring 6, 22297 Hamburg', 4.6],
            ['Selgros Cash & Carry', 'Großhändler', 'Michael Wagner', 'service@selgros.de', '+49 6102 790-0', 'Waldstraße 51, 63263 Neu-Isenburg', 4.2],
            ['Bio-Großhandel Dennree', 'Bio-Händler', 'Lisa Bauer', 'info@dennree.de', '+49 9295 18-0', 'Hofer Straße 11, 95183 Töpen', 4.8],
            ['Frischeparadies', 'Spezialitäten', 'Andreas Koch', 'bestellung@frischeparadies.de', '+49 69 9675-0', 'Große Friedberger Str. 27-33, 60313 Frankfurt', 4.9]
        ];
        
        const supplierIds = [];
        for (const supplier of suppliers) {
            const result = await db.query(
                `INSERT INTO suppliers (tenant_id, name, type, contact_person, email, phone, address, rating, status) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active') RETURNING id`,
                [tenantId, ...supplier]
            );
            supplierIds.push(result.rows[0].id);
        }
        console.log(`✅ Inserted ${supplierIds.length} suppliers`);
        
        // Insert products
        const products = [
            // Gemüse
            ['Kartoffeln festkochend', 'Gemüse', '25kg Sack', 18.50, 120, 40, 200, 0, 'Lager 1 - Kühl'],
            ['Tomaten', 'Gemüse', '5kg Kiste', 14.50, 80, 30, 150, 1, 'Lager 1 - Kühl'],
            ['Zwiebeln', 'Gemüse', '10kg Netz', 11.90, 150, 40, 250, 2, 'Lager 2 - Trocken'],
            ['Möhren', 'Gemüse', '10kg Sack', 9.90, 130, 35, 200, 3, 'Lager 1 - Kühl'],
            ['Paprika rot', 'Gemüse', '5kg Kiste', 18.90, 70, 25, 120, 4, 'Lager 1 - Kühl'],
            ['Brokkoli', 'Gemüse', '5kg Kiste', 16.50, 60, 20, 100, 5, 'Lager 1 - Kühl'],
            ['Blumenkohl', 'Gemüse', '5kg Kiste', 14.90, 55, 20, 90, 0, 'Lager 1 - Kühl'],
            ['Zucchini', 'Gemüse', '5kg Kiste', 13.50, 45, 15, 80, 1, 'Lager 1 - Kühl'],
            ['Spinat TK', 'Gemüse', '10kg Karton', 22.90, 80, 30, 120, 2, 'Lager 3 - TK'],
            ['Erbsen TK', 'Gemüse', '10kg Karton', 19.90, 75, 25, 110, 3, 'Lager 3 - TK'],
            
            // Fleisch
            ['Rindergulasch', 'Fleisch', '5kg Packung', 54.50, 40, 15, 60, 0, 'Lager 1 - Kühl'],
            ['Hähnchenbrust', 'Fleisch', '5kg Packung', 48.90, 60, 20, 100, 1, 'Lager 1 - Kühl'],
            ['Schweineschnitzel', 'Fleisch', '5kg Packung', 39.90, 55, 20, 90, 2, 'Lager 1 - Kühl'],
            ['Hackfleisch gemischt', 'Fleisch', '5kg Packung', 34.50, 50, 20, 80, 3, 'Lager 1 - Kühl'],
            ['Bratwurst', 'Fleisch', '5kg Packung', 36.90, 45, 15, 70, 4, 'Lager 1 - Kühl'],
            ['Hähnchenschenkel', 'Fleisch', '5kg Packung', 29.90, 40, 15, 65, 0, 'Lager 1 - Kühl'],
            ['Schweinebraten', 'Fleisch', '5kg Stück', 44.50, 35, 10, 50, 1, 'Lager 1 - Kühl'],
            ['Rinderbraten', 'Fleisch', '5kg Stück', 69.90, 25, 8, 40, 2, 'Lager 1 - Kühl'],
            ['Lammkeule', 'Fleisch', '3kg Stück', 89.90, 15, 5, 25, 6, 'Lager 1 - Kühl'],
            ['Entenbrust', 'Fleisch', '2kg Packung', 49.90, 20, 5, 30, 6, 'Lager 1 - Kühl'],
            
            // Fisch
            ['Lachs frisch', 'Fisch', '5kg Filet', 124.90, 20, 8, 35, 6, 'Lager 1 - Kühl'],
            ['Forelle', 'Fisch', '5kg Kiste', 89.90, 15, 5, 25, 6, 'Lager 1 - Kühl'],
            ['Kabeljau', 'Fisch', '5kg Filet', 94.90, 18, 6, 30, 6, 'Lager 1 - Kühl'],
            ['Fischstäbchen TK', 'Fisch', '5kg Karton', 34.90, 40, 15, 60, 2, 'Lager 3 - TK'],
            ['Garnelen TK', 'Fisch', '2kg Beutel', 69.90, 25, 10, 40, 6, 'Lager 3 - TK'],
            
            // Grundnahrung
            ['Reis Langkorn', 'Grundnahrung', '10kg Sack', 22.90, 200, 50, 300, 1, 'Lager 2 - Trocken'],
            ['Nudeln Penne', 'Grundnahrung', '5kg Karton', 12.50, 180, 50, 250, 0, 'Lager 2 - Trocken'],
            ['Nudeln Spaghetti', 'Grundnahrung', '5kg Karton', 12.50, 175, 50, 250, 1, 'Lager 2 - Trocken'],
            ['Mehl Type 405', 'Grundnahrung', '25kg Sack', 19.90, 100, 30, 150, 2, 'Lager 2 - Trocken'],
            ['Zucker', 'Grundnahrung', '25kg Sack', 24.90, 80, 25, 120, 3, 'Lager 2 - Trocken'],
            
            // Milchprodukte
            ['Milch 3,5%', 'Milchprodukte', '12L Karton', 13.20, 60, 20, 100, 4, 'Lager 1 - Kühl'],
            ['Sahne', 'Milchprodukte', '12x1L', 35.40, 40, 15, 70, 4, 'Lager 1 - Kühl'],
            ['Butter', 'Milchprodukte', '10kg Karton', 89.90, 30, 10, 50, 4, 'Lager 1 - Kühl'],
            ['Käse Gouda', 'Milchprodukte', '5kg Block', 64.50, 25, 8, 40, 4, 'Lager 1 - Kühl'],
            ['Eier Größe M', 'Milchprodukte', '30er Karton', 8.70, 100, 30, 150, 5, 'Lager 1 - Kühl']
        ];
        
        const productIds = [];
        for (const product of products) {
            const supplierId = supplierIds[product[7]];
            const result = await db.query(
                `INSERT INTO products (tenant_id, name, category, unit, price, stock, min_stock, max_stock, supplier_id, storage_location) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
                [tenantId, product[0], product[1], product[2], product[3], product[4], product[5], product[6], supplierId, product[8]]
            );
            productIds.push(result.rows[0].id);
        }
        console.log(`✅ Inserted ${productIds.length} products`);
        
        // Insert recipes
        const recipes = [
            ['Rindergulasch mit Spätzle', 'lunch', 500, 45, 180, 3.90, 'Traditionell,Fleisch,Beliebt'],
            ['Hähnchenschnitzel paniert', 'lunch', 400, 60, 30, 3.80, 'Fleisch,Klassiker'],
            ['Gemüselasagne', 'lunch', 350, 60, 60, 2.40, 'Vegetarisch,Beliebt'],
            ['Hähnchencurry mit Basmatireis', 'lunch', 450, 40, 60, 3.41, 'Fleisch,International,Scharf'],
            ['Spaghetti Bolognese', 'lunch', 600, 30, 120, 2.91, 'Fleisch,Italienisch,Beliebt'],
            ['Chili sin Carne', 'lunch', 500, 30, 60, 1.90, 'Vegan,Beliebt,Protein'],
            ['Fischstäbchen mit Kartoffelsalat', 'lunch', 450, 20, 20, 2.90, 'Fisch,Beliebt,Kinder'],
            ['Käsespätzle mit Röstzwiebeln', 'lunch', 400, 45, 30, 2.30, 'Vegetarisch,Regional,Beliebt'],
            ['Schweinebraten mit Knödeln', 'lunch', 350, 60, 150, 4.20, 'Fleisch,Regional,Sonntag'],
            ['Linsensuppe mit Würstchen', 'lunch', 600, 30, 90, 1.80, 'Deftig,Günstig,Winter'],
            ['Pizza Margherita', 'lunch', 400, 30, 20, 2.10, 'Italienisch,Vegetarisch,Beliebt'],
            ['Bratwurst mit Sauerkraut', 'lunch', 500, 20, 25, 2.50, 'Fleisch,Regional,Schnell'],
            ['Lachsfilet mit Reis', 'lunch', 300, 25, 20, 5.20, 'Fisch,Gesund,Edel'],
            ['Erbsensuppe', 'lunch', 550, 20, 60, 1.50, 'Vegetarisch,Günstig,Winter'],
            ['Königsberger Klopse', 'lunch', 400, 45, 40, 3.30, 'Fleisch,Traditionell'],
            ['Kartoffelsuppe', 'dinner', 400, 30, 45, 1.30, 'Suppe,Vegetarisch,Günstig'],
            ['Caesar Salad mit Hähnchen', 'dinner', 300, 40, 20, 3.20, 'Salat,Fleisch,Beliebt'],
            ['Brotzeit-Teller', 'dinner', 350, 15, 0, 2.80, 'Kalt,Regional,Schnell'],
            ['Tomatensuppe', 'dinner', 450, 20, 30, 1.20, 'Suppe,Vegetarisch,Beliebt'],
            ['Griechischer Salat', 'dinner', 350, 20, 0, 2.60, 'Salat,Vegetarisch,Gesund']
        ];
        
        for (const recipe of recipes.slice(0, 20)) {
            await db.query(
                `INSERT INTO recipes (tenant_id, name, category, portions, prep_time, cook_time, cost_per_portion, tags) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [tenantId, ...recipe]
            );
        }
        console.log(`✅ Inserted ${20} recipes`);
        
        // Add some sample orders
        const orderDate = new Date();
        for (let i = 0; i < 5; i++) {
            const supplierId = supplierIds[i % supplierIds.length];
            const deliveryDate = new Date(orderDate);
            deliveryDate.setDate(deliveryDate.getDate() + 3);
            
            await db.query(
                `INSERT INTO orders (tenant_id, supplier_id, order_date, delivery_date, status, total_amount) 
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [tenantId, supplierId, orderDate, deliveryDate, 'pending', 150 + (i * 50)]
            );
        }
        console.log('✅ Inserted 5 sample orders');
        
        console.log('✅ Database seeding completed successfully!');
        
    } catch (error) {
        console.error('❌ Error seeding database:', error);
        throw error;
    }
}

// Run the seeding
seedDatabase()
    .then(() => {
        console.log('✅ All done!');
        process.exit(0);
    })
    .catch((error) => {
        console.error('❌ Seeding failed:', error);
        process.exit(1);
    });