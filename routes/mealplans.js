const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');

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

router.use(getTenantId);

// GET /api/mealplans - Get meal plans for a week
router.get('/', async (req, res) => {
    try {
        const { week, year } = req.query;
        const currentWeek = week || 3;
        const currentYear = year || 2024;
        
        const mealPlans = await db.query(`
            SELECT mp.*, r.name as recipe_name, r.cost_per_portion, r.prep_time, r.cook_time
            FROM meal_plans mp
            LEFT JOIN recipes r ON mp.recipe_id = r.id
            WHERE mp.tenant_id = ? AND mp.week_number = ? AND mp.year = ?
            ORDER BY mp.day_of_week, mp.meal_type
        `, [req.tenantId, currentWeek, currentYear]);
        
        // Structure data by day and meal type
        const weekPlan = {};
        const days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
        
        for (let i = 1; i <= 7; i++) {
            weekPlan[days[i-1]] = {
                breakfast: null,
                lunch: null,
                dinner: null
            };
        }
        
        for (const plan of mealPlans) {
            const dayName = days[plan.day_of_week - 1];
            weekPlan[dayName][plan.meal_type] = plan;
        }
        
        res.json({
            week: currentWeek,
            year: currentYear,
            plan: weekPlan
        });
    } catch (error) {
        console.error('Error fetching meal plans:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// PUT /api/mealplans - Update meal plan
router.put('/', async (req, res) => {
    try {
        const { week, year, day_of_week, meal_type, recipe_id, planned_portions } = req.body;
        
        if (!week || !year || !day_of_week || !meal_type) {
            return res.status(400).json({ error: 'Week, year, day_of_week, and meal_type are required' });
        }
        
        // Check if meal plan exists
        const existing = await db.get(`
            SELECT id FROM meal_plans 
            WHERE tenant_id = ? AND week_number = ? AND year = ? AND day_of_week = ? AND meal_type = ?
        `, [req.tenantId, week, year, day_of_week, meal_type]);
        
        if (existing) {
            // Update existing
            if (recipe_id) {
                await db.run(`
                    UPDATE meal_plans 
                    SET recipe_id = ?, planned_portions = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                `, [recipe_id, planned_portions || 1, existing.id]);
            } else {
                // Remove meal plan
                await db.run('DELETE FROM meal_plans WHERE id = ?', [existing.id]);
            }
        } else if (recipe_id) {
            // Create new
            await db.create('meal_plans', {
                tenant_id: req.tenantId,
                week_number: week,
                year: year,
                day_of_week: day_of_week,
                meal_type: meal_type,
                recipe_id: recipe_id,
                planned_portions: planned_portions || 1
            });
        }
        
        res.json({ message: 'Meal plan updated successfully' });
    } catch (error) {
        console.error('Error updating meal plan:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;