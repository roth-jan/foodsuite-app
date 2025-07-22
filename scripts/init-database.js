const db = require('../database/db-simple');

async function initDatabase() {
    try {
        console.log('🔄 Initializing FoodSuite database...');
        
        await db.initialize();
        console.log('✅ Database initialized successfully');
        
        // Create default tenant if not exists
        const existingTenant = await db.get(
            'SELECT * FROM tenants WHERE tenant_key = ?', 
            ['demo']
        );
        
        if (!existingTenant) {
            await db.create('tenants', {
                tenant_key: 'demo',
                name: 'Demo Restaurant',
                email: 'demo@foodsuite.com',
                phone: '+49 123 456789',
                address: 'Musterstraße 123, 12345 Musterstadt',
                current_week: 3,
                ai_mode: 'cost'
            });
            console.log('✅ Default tenant created');
        }
        
        await db.close();
        console.log('🎉 Database initialization completed!');
        process.exit(0);
        
    } catch (error) {
        console.error('❌ Database initialization failed:', error);
        process.exit(1);
    }
}

initDatabase();