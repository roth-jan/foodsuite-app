const db = require('./postgres-client');

async function addMoreData() {
    console.log('📦 Adding more products and recipes to PostgreSQL...');
    
    try {
        const tenantId = 1; // demo tenant
        
        // Check current counts
        const productCount = await db.query('SELECT COUNT(*) FROM products WHERE tenant_id = $1', [tenantId]);
        const recipeCount = await db.query('SELECT COUNT(*) FROM recipes WHERE tenant_id = $1', [tenantId]);
        
        console.log(`Current: ${productCount.rows[0].count} products, ${recipeCount.rows[0].count} recipes`);
        
        // Get existing supplier IDs
        const suppliers = await db.query('SELECT id FROM suppliers WHERE tenant_id = $1', [tenantId]);
        const supplierIds = suppliers.rows.map(s => s.id);
        
        // Add more products (to reach 150)
        const additionalProducts = [
            // Gewürze & Kräuter
            ['Salz fein', 'Gewürze', '25kg Sack', 8.90, 200, 50, 300],
            ['Pfeffer schwarz gemahlen', 'Gewürze', '1kg Dose', 24.90, 40, 10, 60],
            ['Paprikapulver edelsüß', 'Gewürze', '1kg Dose', 18.90, 35, 10, 50],
            ['Curry Pulver', 'Gewürze', '1kg Dose', 22.50, 30, 8, 45],
            ['Oregano getrocknet', 'Gewürze', '500g Dose', 14.90, 25, 8, 40],
            ['Basilikum getrocknet', 'Gewürze', '500g Dose', 16.90, 25, 8, 40],
            ['Thymian getrocknet', 'Gewürze', '500g Dose', 15.90, 20, 5, 35],
            ['Rosmarin getrocknet', 'Gewürze', '500g Dose', 17.90, 20, 5, 35],
            ['Knoblauchpulver', 'Gewürze', '1kg Dose', 19.90, 30, 10, 45],
            ['Zwiebelpulver', 'Gewürze', '1kg Dose', 18.50, 30, 10, 45],
            
            // Konserven
            ['Tomaten geschält Dose', 'Konserven', '12x800g', 18.90, 100, 30, 150],
            ['Tomatenmark', 'Konserven', '12x200g', 14.50, 80, 25, 120],
            ['Mais Dose', 'Konserven', '12x340g', 16.90, 60, 20, 90],
            ['Champignons geschnitten', 'Konserven', '12x800g', 42.90, 40, 15, 60],
            ['Kidney Bohnen', 'Konserven', '12x800g', 22.90, 50, 15, 75],
            ['Kichererbsen', 'Konserven', '12x800g', 24.90, 45, 15, 70],
            ['Ananas Stücke', 'Konserven', '12x850g', 32.90, 30, 10, 50],
            ['Pfirsiche halbe Frucht', 'Konserven', '12x850g', 34.90, 25, 8, 40],
            
            // Backwaren
            ['Weizenmehl Type 550', 'Backwaren', '25kg Sack', 21.90, 80, 25, 120],
            ['Backpulver', 'Backwaren', '5kg Eimer', 32.50, 20, 5, 30],
            ['Hefe frisch', 'Backwaren', '42g Würfel', 0.89, 100, 30, 150],
            ['Vanillezucker', 'Backwaren', '1kg Packung', 12.90, 40, 10, 60],
            ['Kakaopulver', 'Backwaren', '1kg Dose', 18.90, 30, 10, 45],
            
            // Öle & Fette
            ['Sonnenblumenöl', 'Öle', '10L Kanister', 32.90, 60, 20, 90],
            ['Rapsöl', 'Öle', '10L Kanister', 29.90, 55, 20, 85],
            ['Olivenöl Extra Vergine', 'Öle', '5L Kanister', 84.90, 30, 10, 45],
            ['Kokosfett', 'Öle', '10kg Eimer', 45.90, 25, 8, 40],
            ['Margarine', 'Öle', '10kg Karton', 38.90, 40, 15, 60],
            
            // Getränke
            ['Orangensaft', 'Getränke', '12x1L', 28.90, 40, 15, 60],
            ['Apfelsaft', 'Getränke', '12x1L', 24.90, 45, 15, 65],
            ['Mineralwasser still', 'Getränke', '12x1L', 8.90, 100, 30, 150],
            ['Mineralwasser spritzig', 'Getränke', '12x1L', 8.90, 100, 30, 150],
            ['Cola', 'Getränke', '12x1L', 18.90, 60, 20, 90],
            
            // Milchprodukte erweitert
            ['Joghurt natur', 'Milchprodukte', '10kg Eimer', 24.90, 40, 15, 60],
            ['Schmand', 'Milchprodukte', '5kg Eimer', 19.90, 35, 10, 50],
            ['Crème fraîche', 'Milchprodukte', '5kg Eimer', 22.90, 30, 10, 45],
            ['Mozzarella', 'Milchprodukte', '3kg Packung', 28.90, 25, 8, 40],
            ['Parmesan gerieben', 'Milchprodukte', '1kg Beutel', 34.90, 20, 5, 30],
            
            // Tiefkühlprodukte
            ['Pommes Frites TK', 'Tiefkühl', '10kg Karton', 18.90, 80, 25, 120],
            ['Gemüsemischung TK', 'Tiefkühl', '10kg Karton', 24.90, 60, 20, 90],
            ['Beerenmischung TK', 'Tiefkühl', '10kg Karton', 42.90, 30, 10, 45],
            ['Pizza Margherita TK', 'Tiefkühl', '20 Stück', 49.90, 40, 15, 60],
            ['Frühlingsrollen TK', 'Tiefkühl', '60 Stück', 54.90, 35, 10, 50],
            
            // Fleisch erweitert
            ['Putenbrust', 'Fleisch', '5kg Packung', 52.90, 35, 10, 50],
            ['Lammhackfleisch', 'Fleisch', '5kg Packung', 64.90, 20, 5, 30],
            ['Kalbsschnitzel', 'Fleisch', '5kg Packung', 89.90, 15, 5, 25],
            ['Leberkäse', 'Fleisch', '3kg Stück', 28.90, 30, 10, 45],
            ['Wiener Würstchen', 'Fleisch', '5kg Packung', 42.90, 40, 15, 60],
            
            // Fisch erweitert
            ['Thunfisch in Öl', 'Fisch', '24x195g', 68.90, 50, 15, 75],
            ['Seelachs TK', 'Fisch', '5kg Filet', 74.90, 25, 8, 40],
            ['Matjes', 'Fisch', '5kg Eimer', 64.90, 20, 5, 30],
            ['Räucherlachs', 'Fisch', '1kg Packung', 89.90, 15, 5, 25],
            
            // Saucen & Dressings
            ['Ketchup', 'Saucen', '10kg Eimer', 22.90, 60, 20, 90],
            ['Mayonnaise', 'Saucen', '10kg Eimer', 28.90, 55, 20, 85],
            ['Senf mittelscharf', 'Saucen', '10kg Eimer', 24.90, 40, 15, 60],
            ['Balsamico Creme', 'Saucen', '3L Flasche', 32.90, 30, 10, 45],
            ['Sojasauce', 'Saucen', '5L Kanister', 34.90, 35, 10, 50],
            ['Worcestersauce', 'Saucen', '1L Flasche', 18.90, 25, 8, 40],
            
            // Nudeln & Teigwaren
            ['Spaghetti', 'Grundnahrung', '5kg Karton', 12.50, 180, 50, 250],
            ['Fusilli', 'Grundnahrung', '5kg Karton', 12.50, 160, 45, 220],
            ['Lasagneplatten', 'Grundnahrung', '5kg Karton', 14.90, 80, 25, 120],
            ['Tagliatelle', 'Grundnahrung', '5kg Karton', 16.90, 70, 20, 100],
            ['Gnocchi', 'Grundnahrung', '5kg Packung', 22.90, 60, 20, 90],
            
            // Süßwaren & Desserts
            ['Pudding Vanille', 'Süßwaren', '5kg Eimer', 18.90, 40, 15, 60],
            ['Schokolade Vollmilch', 'Süßwaren', '5kg Block', 42.90, 30, 10, 45],
            ['Honig', 'Süßwaren', '5kg Eimer', 54.90, 25, 8, 40],
            ['Nutella', 'Süßwaren', '3kg Eimer', 32.90, 35, 10, 50],
            ['Marmelade Erdbeere', 'Süßwaren', '5kg Eimer', 28.90, 30, 10, 45],
            
            // Internationale Zutaten
            ['Couscous', 'International', '5kg Sack', 24.90, 40, 15, 60],
            ['Quinoa', 'International', '5kg Sack', 84.90, 20, 5, 30],
            ['Bulgur', 'International', '5kg Sack', 22.90, 35, 10, 50],
            ['Kokosmilch', 'International', '12x400ml', 36.90, 45, 15, 65],
            ['Reispapier', 'International', '500 Blatt', 28.90, 20, 5, 30]
        ];
        
        let addedProducts = 0;
        for (const product of additionalProducts) {
            const supplierId = supplierIds[Math.floor(Math.random() * supplierIds.length)];
            try {
                await db.query(
                    `INSERT INTO products (tenant_id, name, category, unit, price, stock, min_stock, max_stock, supplier_id, storage_location) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
                    [tenantId, product[0], product[1], product[2], product[3], product[4], product[5], product[6], supplierId, 'Lager']
                );
                addedProducts++;
            } catch (e) {
                console.log(`Skipping duplicate: ${product[0]}`);
            }
        }
        
        console.log(`✅ Added ${addedProducts} new products`);
        
        // Add more recipes (to reach 75)
        const additionalRecipes = [
            // Hauptgerichte Mittag
            ['Wiener Schnitzel mit Pommes', 'lunch', 450, 30, 25, 4.50, 'Fleisch,Österreichisch,Klassiker'],
            ['Jägerschnitzel mit Spätzle', 'lunch', 400, 35, 30, 4.20, 'Fleisch,Deutsch,Deftig'],
            ['Cordon Bleu mit Kartoffelsalat', 'lunch', 350, 40, 30, 5.10, 'Fleisch,Käse,Beliebt'],
            ['Hähnchen süß-sauer mit Reis', 'lunch', 500, 35, 25, 3.60, 'Fleisch,Asiatisch,Beliebt'],
            ['Gyros mit Tzatziki', 'lunch', 450, 30, 20, 3.80, 'Fleisch,Griechisch,Beliebt'],
            ['Döner Teller', 'lunch', 400, 25, 15, 4.20, 'Fleisch,Türkisch,Streetfood'],
            ['Frikadellen mit Kartoffelpüree', 'lunch', 500, 30, 20, 3.20, 'Fleisch,Deutsch,Klassiker'],
            ['Leberkäse mit Spiegelei', 'lunch', 450, 15, 10, 2.90, 'Fleisch,Bayrisch,Deftig'],
            ['Currywurst mit Pommes', 'lunch', 550, 20, 15, 2.80, 'Fleisch,Deutsch,Imbiss'],
            ['Pulled Pork Burger', 'lunch', 350, 45, 180, 4.90, 'Fleisch,Amerikanisch,Trendy'],
            
            // Vegetarisch/Vegan Mittag
            ['Gemüsecurry mit Naan', 'lunch', 400, 30, 25, 2.60, 'Vegan,Indisch,Scharf'],
            ['Falafel mit Hummus', 'lunch', 450, 35, 20, 2.40, 'Vegan,Orientalisch,Protein'],
            ['Tofu-Gemüse-Pfanne', 'lunch', 500, 25, 20, 2.20, 'Vegan,Asiatisch,Gesund'],
            ['Quinoa-Bowl', 'lunch', 350, 30, 15, 3.10, 'Vegan,Trendy,Superfood'],
            ['Veggie-Burger', 'lunch', 400, 35, 20, 2.80, 'Vegetarisch,Amerikanisch,Trendy'],
            ['Spinat-Ricotta-Cannelloni', 'lunch', 350, 40, 35, 2.90, 'Vegetarisch,Italienisch,Käse'],
            ['Kürbissuppe mit Brot', 'lunch', 450, 25, 30, 1.80, 'Vegan,Herbst,Suppe'],
            ['Ratatouille mit Reis', 'lunch', 400, 35, 40, 2.10, 'Vegan,Französisch,Gemüse'],
            ['Pilzragout mit Knödeln', 'lunch', 380, 30, 25, 2.70, 'Vegetarisch,Herbst,Regional'],
            ['Zucchini-Lasagne', 'lunch', 320, 45, 40, 2.50, 'Vegetarisch,Low-Carb,Gesund'],
            
            // Fisch Mittag
            ['Backfisch mit Remoulade', 'lunch', 400, 25, 20, 4.80, 'Fisch,Norddeutsch,Klassiker'],
            ['Lachsfilet mit Dillsauce', 'lunch', 300, 30, 25, 6.20, 'Fisch,Edel,Gesund'],
            ['Forelle Müllerin Art', 'lunch', 350, 35, 20, 5.50, 'Fisch,Klassisch,Regional'],
            ['Fish & Chips', 'lunch', 450, 30, 25, 4.20, 'Fisch,Britisch,Beliebt'],
            ['Seelachs mit Senfsauce', 'lunch', 400, 25, 20, 3.90, 'Fisch,Günstig,Gesund'],
            
            // Pasta Mittag
            ['Carbonara', 'lunch', 500, 25, 15, 3.20, 'Pasta,Italienisch,Beliebt'],
            ['Penne Arrabbiata', 'lunch', 550, 20, 15, 2.40, 'Pasta,Scharf,Vegan'],
            ['Tortellini in Sahnesauce', 'lunch', 450, 20, 10, 3.50, 'Pasta,Italienisch,Schnell'],
            ['Pasta Primavera', 'lunch', 500, 30, 20, 2.60, 'Pasta,Vegetarisch,Frühling'],
            ['Maccheroni Auflauf', 'lunch', 400, 35, 40, 2.80, 'Pasta,Überbacken,Käse'],
            
            // Suppen & Eintöpfe Mittag
            ['Gulaschsuppe', 'lunch', 500, 30, 90, 2.20, 'Suppe,Fleisch,Deftig'],
            ['Minestrone', 'lunch', 450, 25, 40, 1.80, 'Suppe,Italienisch,Vegetarisch'],
            ['Hühnersuppe', 'lunch', 550, 20, 60, 1.90, 'Suppe,Fleisch,Gesund'],
            ['Kürbiscremesuppe', 'lunch', 400, 25, 30, 1.60, 'Suppe,Vegetarisch,Herbst'],
            ['Zwiebelsuppe', 'lunch', 350, 30, 40, 1.40, 'Suppe,Vegetarisch,Französisch'],
            
            // Abendessen erweitert
            ['Flammkuchen Elsässer Art', 'dinner', 300, 20, 15, 2.90, 'Abend,Elsässisch,Zwiebel'],
            ['Quiche Lorraine', 'dinner', 280, 35, 30, 3.20, 'Abend,Französisch,Speck'],
            ['Antipasti-Platte', 'dinner', 250, 20, 0, 3.80, 'Abend,Italienisch,Kalt'],
            ['Käseplatte mit Brot', 'dinner', 300, 15, 0, 3.50, 'Abend,Kalt,Käse'],
            ['Wraps mit Hähnchen', 'dinner', 350, 25, 10, 2.80, 'Abend,Mexikanisch,Beliebt'],
            ['Bagel mit Lachs', 'dinner', 280, 20, 0, 4.20, 'Abend,Amerikanisch,Fisch'],
            ['Bruschetta', 'dinner', 320, 15, 5, 2.10, 'Abend,Italienisch,Vegan'],
            ['Gemüsesticks mit Dips', 'dinner', 400, 20, 0, 1.80, 'Abend,Gesund,Vegetarisch'],
            ['Ofenkartoffel mit Quark', 'dinner', 350, 15, 45, 1.90, 'Abend,Vegetarisch,Einfach'],
            ['Mozzarella-Tomaten-Salat', 'dinner', 300, 15, 0, 2.60, 'Abend,Italienisch,Sommer'],
            
            // Desserts
            ['Apfelstrudel', 'dessert', 200, 30, 40, 1.20, 'Dessert,Österreichisch,Süß'],
            ['Tiramisu', 'dessert', 180, 45, 0, 1.80, 'Dessert,Italienisch,Kaffee'],
            ['Panna Cotta', 'dessert', 150, 30, 120, 1.50, 'Dessert,Italienisch,Süß'],
            ['Crème Brûlée', 'dessert', 120, 40, 180, 2.20, 'Dessert,Französisch,Edel'],
            ['Kaiserschmarrn', 'dessert', 250, 25, 15, 1.90, 'Dessert,Österreichisch,Süß']
        ];
        
        let addedRecipes = 0;
        for (const recipe of additionalRecipes) {
            try {
                await db.query(
                    `INSERT INTO recipes (tenant_id, name, category, portions, prep_time, cook_time, cost_per_portion, tags) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                    [tenantId, ...recipe]
                );
                addedRecipes++;
            } catch (e) {
                console.log(`Skipping duplicate: ${recipe[0]}`);
            }
        }
        
        console.log(`✅ Added ${addedRecipes} new recipes`);
        
        // Final count
        const finalProductCount = await db.query('SELECT COUNT(*) FROM products WHERE tenant_id = $1', [tenantId]);
        const finalRecipeCount = await db.query('SELECT COUNT(*) FROM recipes WHERE tenant_id = $1', [tenantId]);
        
        console.log(`\n✅ Final counts: ${finalProductCount.rows[0].count} products, ${finalRecipeCount.rows[0].count} recipes`);
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
    
    process.exit(0);
}

addMoreData();