require('dotenv').config();

const express = require('express');
const router = express.Router();
const dbType = process.env.DB_TYPE || 'memory';
const db = dbType === 'postgres' ? require('../database/postgres-adapter') : require('../database/db-memory');
const Joi = require('joi');

// Validation schemas
const recipeIngredientSchema = Joi.object({
    product_id: Joi.number().integer().required(),
    quantity: Joi.number().positive().required(),
    unit: Joi.string().required()
});

const recipeSchema = Joi.object({
    name: Joi.string().required(),
    category_id: Joi.number().integer().required(),
    portions: Joi.number().integer().min(1).default(4),
    prep_time: Joi.number().integer().min(0).default(30),
    cook_time: Joi.number().integer().min(0).default(30),
    instructions: Joi.string().required(),
    notes: Joi.string().optional(),
    tags: Joi.string().optional(),
    ingredients: Joi.array().items(recipeIngredientSchema).min(1).required()
});

// Helper function to get tenant ID
function getTenantId(req, res, next) {
    const tenantKey = req.headers['x-tenant-id'] || 'demo';
    
    if (process.env.DB_TYPE === 'postgres') {
        req.tenantId = 1; // Always use tenant 1 for demo
        next();
        return;
    }
    
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

// GET /api/recipes - Get all recipes
router.get('/', async (req, res) => {
    try {
        const { page = 1, limit = 60, search, category, tags } = req.query;
        
        // Use adapter method if available (PostgreSQL)
        if (db.getRecipes) {
            const filters = {
                search,
                category,
                tags,
                limit: parseInt(limit),
                offset: (parseInt(page) - 1) * parseInt(limit)
            };
            
            const recipes = await db.getRecipes(req.tenantId, filters);
            
            res.json({
                items: recipes,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalItems: recipes.length,
                    totalPages: Math.ceil(recipes.length / limit)
                }
            });
            return;
        }
        
        // Fallback for in-memory database
        const allRecipes = db.data.recipes || [];
        
        // Filter by tenant
        let filteredRecipes = allRecipes.filter(recipe => recipe.tenant_id === req.tenantId);
        
        if (search) {
            filteredRecipes = filteredRecipes.filter(recipe => 
                recipe.name.toLowerCase().includes(search.toLowerCase())
            );
        }
        
        if (category) {
            filteredRecipes = filteredRecipes.filter(recipe => 
                recipe.category_id === parseInt(category)
            );
        }
        
        if (tags) {
            filteredRecipes = filteredRecipes.filter(recipe => 
                recipe.tags && recipe.tags.toLowerCase().includes(tags.toLowerCase())
            );
        }
        
        // Sort by name
        filteredRecipes.sort((a, b) => a.name.localeCompare(b.name));
        
        // Pagination
        const startIndex = (parseInt(page) - 1) * parseInt(limit);
        const endIndex = startIndex + parseInt(limit);
        const paginatedRecipes = filteredRecipes.slice(startIndex, endIndex);
        
        const result = {
            items: paginatedRecipes,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalItems: filteredRecipes.length,
                totalPages: Math.ceil(filteredRecipes.length / parseInt(limit)),
                hasNextPage: endIndex < filteredRecipes.length,
                hasPreviousPage: parseInt(page) > 1
            }
        };
        
        // Enrich with category and calculate cost
        for (let recipe of result.items) {
            if (recipe.category_id) {
                const recipeCategories = db.data.recipe_categories || [];
                recipe.category = recipeCategories.find(cat => cat.id === recipe.category_id);
            }
            
            // Get ingredients from in-memory database
            const recipeIngredients = db.data.recipe_ingredients || [];
            const products = db.data.products || [];
            
            const ingredients = recipeIngredients
                .filter(ri => ri.recipe_id === recipe.id)
                .map(ri => {
                    const product = products.find(p => p.id === ri.product_id);
                    return {
                        ...ri,
                        product_name: product ? product.name : 'Unknown Product',
                        price: product ? product.price : 0,
                        product_unit: product ? product.unit : 'kg'
                    };
                });
            
            let totalCost = 0;
            for (const ingredient of ingredients) {
                totalCost += ingredient.quantity * ingredient.price;
            }
            
            recipe.cost_per_portion = totalCost / recipe.portions;
            recipe.ingredients = ingredients;
        }
        
        res.json(result);
    } catch (error) {
        console.error('Error fetching recipes:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/recipes/:id - Get single recipe
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const recipe = await db.findById('recipes', id, req.tenantId);
        
        if (!recipe) {
            return res.status(404).json({ error: 'Recipe not found' });
        }
        
        // Enrich with category
        if (recipe.category_id) {
            const recipeCategories = db.data.recipe_categories || [];
            recipe.category = recipeCategories.find(cat => cat.id === recipe.category_id);
        }
        
        // Get ingredients from in-memory database
        const recipeIngredients = db.data.recipe_ingredients || [];
        const products = db.data.products || [];
        
        const ingredients = recipeIngredients
            .filter(ri => ri.recipe_id === parseInt(id))
            .map(ri => {
                const product = products.find(p => p.id === ri.product_id);
                return {
                    ...ri,
                    product_name: product ? product.name : 'Unknown Product',
                    price: product ? product.price : 0,
                    product_unit: product ? product.unit : 'kg',
                    article_number: product ? product.article_number : ''
                };
            });
        
        recipe.ingredients = ingredients;
        
        // Calculate cost
        let totalCost = 0;
        for (const ingredient of ingredients) {
            totalCost += ingredient.quantity * ingredient.price;
        }
        recipe.cost_per_portion = totalCost / recipe.portions;
        
        res.json(recipe);
    } catch (error) {
        console.error('Error fetching recipe:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/recipes - Create new recipe
router.post('/', async (req, res) => {
    try {
        const { error, value } = recipeSchema.validate(req.body);
        
        if (error) {
            return res.status(400).json({ 
                error: 'Validation error', 
                details: error.details 
            });
        }
        
        // Validate ingredients
        for (const ingredient of value.ingredients) {
            const product = await db.findById('products', ingredient.product_id, req.tenantId);
            if (!product) {
                return res.status(400).json({ 
                    error: `Product with ID ${ingredient.product_id} not found` 
                });
            }
        }
        
        // Calculate cost
        let totalCost = 0;
        for (const ingredient of value.ingredients) {
            const product = await db.findById('products', ingredient.product_id, req.tenantId);
            totalCost += ingredient.quantity * product.price;
        }
        
        const recipe = await db.transaction(async (database) => {
            // Create recipe
            const recipeData = {
                tenant_id: req.tenantId,
                name: value.name,
                category_id: value.category_id,
                portions: value.portions,
                prep_time: value.prep_time,
                cook_time: value.cook_time,
                cost_per_portion: totalCost / value.portions,
                instructions: value.instructions,
                notes: value.notes,
                tags: value.tags,
                status: 'active'
            };
            
            const newRecipe = await database.create('recipes', recipeData);
            
            // Create recipe ingredients
            for (const ingredient of value.ingredients) {
                await database.create('recipe_ingredients', {
                    recipe_id: newRecipe.id,
                    product_id: ingredient.product_id,
                    quantity: ingredient.quantity,
                    unit: ingredient.unit
                });
            }
            
            return newRecipe;
        });
        
        // Get complete recipe with ingredients
        const completeRecipe = await db.findById('recipes', recipe.id, req.tenantId);
        completeRecipe.ingredients = value.ingredients;
        
        res.status(201).json(completeRecipe);
    } catch (error) {
        console.error('Error creating recipe:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// GET /api/recipes/categories - Get all recipe categories
router.get('/categories/all', async (req, res) => {
    try {
        const categories = db.data.recipe_categories || [];
        // Sort by name
        const sortedCategories = categories.sort((a, b) => a.name.localeCompare(b.name));
        res.json(sortedCategories);
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;