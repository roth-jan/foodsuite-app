const express = require('express');
const router = express.Router();
const db = require('../database/db-memory');

// Helper function to get tenant ID
function getTenantId(req, res, next) {
    const tenantKey = req.headers['x-tenant-id'] || 'demo';
    const tenants = db.data.tenants || [];
    const tenant = tenants.find(t => t.tenant_key === tenantKey);
    
    if (!tenant) {
        return res.status(404).json({ error: 'Tenant not found' });
    }
    
    req.tenantId = tenant.id;
    next();
}

router.use(getTenantId);

// POST /api/ai/suggest-meals - Generate AI meal plan
router.post('/suggest-meals', async (req, res) => {
    try {
        const { mode = 'cost_optimized', weekNumber = 1, currentPlan = {}, customConfig = null } = req.body;
        
        // Get all recipes with ingredients for nutritional calculation
        const recipes = db.data.recipes.filter(r => r.tenant_id === req.tenantId && r.is_active);
        
        console.log(`🤖 Generating AI meal plan - Mode: ${mode}, Recipes: ${recipes.length}`);
        
        // Debug custom config
        if (mode === 'custom') {
            console.log('🔍 Custom Config received:', customConfig ? 'YES' : 'NO');
            if (customConfig) {
                console.log('   Weights:', customConfig.weights);
                console.log('   Exclusions:', customConfig.exclusions);
            }
        }
        
        if (recipes.length === 0) {
            return res.status(400).json({ error: 'Keine Rezepte verfügbar' });
        }
        
        // Get recipe ingredients for nutritional data
        const recipeIngredients = db.data.recipe_ingredients || [];
        const products = db.data.products || [];
        
        // Calculate nutritional values for each recipe
        const recipesWithNutrition = recipes.map(recipe => {
            const ingredients = recipeIngredients.filter(ri => ri.recipe_id === recipe.id);
            let totalProtein = 0;
            let totalCalories = 0;
            let totalFat = 0;
            let totalCarbs = 0;
            
            ingredients.forEach(ing => {
                const product = products.find(p => p.id === ing.product_id);
                if (product) {
                    // Assume nutritional values per 100g
                    const factor = ing.quantity / 100;
                    totalProtein += (product.protein || 0) * factor;
                    totalCalories += (product.calories || 0) * factor;
                    totalFat += (product.fat || 0) * factor;
                    totalCarbs += (product.carbs || 0) * factor;
                }
            });
            
            return {
                ...recipe,
                nutrition: {
                    protein: totalProtein / (recipe.portions || 1),
                    calories: totalCalories / (recipe.portions || 1),
                    fat: totalFat / (recipe.portions || 1),
                    carbs: totalCarbs / (recipe.portions || 1)
                }
            };
        });
        
        // Generate meal plan based on mode
        const mealPlan = generateMealPlan(recipesWithNutrition, mode, currentPlan, customConfig);
        
        // Calculate statistics
        const stats = calculatePlanStatistics(mealPlan, recipesWithNutrition);
        
        res.json({
            success: true,
            mode,
            weekNumber,
            mealPlan,
            statistics: stats,
            averageCostPerMeal: stats.averageCostPerMeal,
            totalCost: stats.totalCost,
            message: getSuccessMessage(mode, stats)
        });
        
    } catch (error) {
        console.error('Error generating AI meal plan:', error);
        res.status(500).json({ error: 'Fehler bei der KI-Generierung' });
    }
});

// POST /api/ai/optimize-plan - Optimize existing meal plan
router.post('/optimize-plan', async (req, res) => {
    try {
        const { mode = 'cost_optimized', currentPlan = {}, weekNumber = 1 } = req.body;
        
        console.log(`🔧 Optimizing existing meal plan - Mode: ${mode}`);
        
        // Get all recipes with ingredients
        const recipes = db.data.recipes.filter(r => r.tenant_id === req.tenantId && r.is_active);
        
        if (recipes.length === 0) {
            return res.status(400).json({ error: 'Keine Rezepte verfügbar' });
        }
        
        // Get recipe ingredients for nutritional data
        const recipeIngredients = db.data.recipe_ingredients || [];
        const products = db.data.products || [];
        
        // Calculate nutritional values for each recipe
        const recipesWithNutrition = recipes.map(recipe => {
            const ingredients = recipeIngredients.filter(ri => ri.recipe_id === recipe.id);
            let totalProtein = 0;
            let totalCalories = 0;
            let totalFat = 0;
            let totalCarbs = 0;
            
            ingredients.forEach(ing => {
                const product = products.find(p => p.id === ing.product_id);
                if (product) {
                    const factor = ing.quantity / 100;
                    totalProtein += (product.protein || 0) * factor;
                    totalCalories += (product.calories || 0) * factor;
                    totalFat += (product.fat || 0) * factor;
                    totalCarbs += (product.carbs || 0) * factor;
                }
            });
            
            return {
                ...recipe,
                nutrition: {
                    protein: totalProtein / (recipe.portions || 1),
                    calories: totalCalories / (recipe.portions || 1),
                    fat: totalFat / (recipe.portions || 1),
                    carbs: totalCarbs / (recipe.portions || 1)
                }
            };
        });
        
        // Optimize the existing plan
        const optimizedPlan = optimizeExistingPlan(currentPlan, recipesWithNutrition, mode);
        
        // Calculate improvement statistics
        const currentStats = calculatePlanStatistics(currentPlan, recipesWithNutrition);
        const optimizedStats = calculatePlanStatistics(optimizedPlan.mealPlan, recipesWithNutrition);
        
        // Calculate improvements
        const improvements = {
            costReduction: ((currentStats.totalCost - optimizedStats.totalCost) / currentStats.totalCost * 100).toFixed(1),
            nutritionImprovement: ((optimizedStats.totalProtein - currentStats.totalProtein) / currentStats.totalProtein * 100).toFixed(1),
            varietyIncrease: optimizedStats.uniqueRecipes - currentStats.uniqueRecipes
        };
        
        res.json({
            success: true,
            mode,
            weekNumber,
            mealPlan: optimizedPlan.mealPlan,
            suggestions: optimizedPlan.suggestions,
            statistics: optimizedStats,
            improvements,
            message: getOptimizationMessage(mode, improvements, optimizedStats)
        });
        
    } catch (error) {
        console.error('Error optimizing meal plan:', error);
        res.status(500).json({ error: 'Fehler bei der Optimierung' });
    }
});

// Main AI logic for generating meal plans
function generateMealPlan(recipes, mode, currentPlan = {}, customConfig = null) {
    const days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
    const meals = ['breakfast', 'lunch', 'dinner'];
    const plan = {};
    
    // Separate recipes by category
    const breakfastRecipes = recipes.filter(r => r.category === 'breakfast');
    const lunchRecipes = recipes.filter(r => r.category === 'lunch');
    const dinnerRecipes = recipes.filter(r => r.category === 'dinner' || r.category === 'Abendessen');
    
    // Track used recipes for variety
    const usedRecipes = new Set();
    
    days.forEach(day => {
        meals.forEach(meal => {
            const slot = `${day}-${meal}`;
            
            // Skip if already planned
            if (currentPlan[slot]) {
                plan[slot] = currentPlan[slot];
                return;
            }
            
            let selectedRecipe = null;
            let recipePool = [];
            
            // Select appropriate recipe pool
            switch (meal) {
                case 'breakfast':
                    recipePool = breakfastRecipes.length > 0 ? breakfastRecipes : recipes;
                    break;
                case 'lunch':
                    recipePool = lunchRecipes.length > 0 ? lunchRecipes : recipes;
                    break;
                case 'dinner':
                    recipePool = dinnerRecipes.length > 0 ? dinnerRecipes : recipes;
                    break;
            }
            
            // Apply AI selection based on mode
            if (mode === 'custom' && customConfig) {
                selectedRecipe = selectCustomMode(recipePool, usedRecipes, meal, customConfig);
            } else {
                switch (mode) {
                    case 'cost_optimized':
                        selectedRecipe = selectCostOptimized(recipePool, usedRecipes);
                        break;
                        
                    case 'balanced_nutrition':
                        selectedRecipe = selectBalancedNutrition(recipePool, usedRecipes, meal);
                        break;
                        
                    case 'variety':
                        selectedRecipe = selectMaxVariety(recipePool, usedRecipes);
                        break;
                        
                    case 'seasonal':
                        selectedRecipe = selectSeasonal(recipePool, usedRecipes);
                        break;
                        
                    case 'inventory_based':
                        selectedRecipe = selectInventoryBased(recipePool, usedRecipes);
                        break;
                        
                    default:
                        selectedRecipe = selectCostOptimized(recipePool, usedRecipes);
                }
            }
            
            if (selectedRecipe) {
                plan[slot] = {
                    id: selectedRecipe.id,
                    name: selectedRecipe.name,
                    cost_per_portion: selectedRecipe.cost_per_portion || selectedRecipe.cost || 3.50,
                    portions: selectedRecipe.portions || 50
                };
                usedRecipes.add(selectedRecipe.id);
            }
        });
    });
    
    return plan;
}

// AI Mode: Cost Optimized - Select cheapest recipes
function selectCostOptimized(recipes, usedRecipes) {
    const available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) return recipes[0]; // Fallback if all used
    
    // Sort by cost per portion
    available.sort((a, b) => (a.cost_per_portion || 0) - (b.cost_per_portion || 0));
    
    // Take one of the cheapest 3 for some variety
    const topCheap = available.slice(0, 3);
    return topCheap[Math.floor(Math.random() * topCheap.length)];
}

// AI Mode: Balanced Nutrition - Optimize for nutritional balance
function selectBalancedNutrition(recipes, usedRecipes, mealType) {
    const available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) return recipes[0];
    
    // Define ideal nutritional targets per meal
    const targets = {
        breakfast: { protein: 15, calories: 400, carbs: 50, fat: 10 },
        lunch: { protein: 30, calories: 600, carbs: 70, fat: 20 },
        dinner: { protein: 25, calories: 500, carbs: 60, fat: 15 }
    };
    
    const target = targets[mealType] || targets.lunch;
    
    // Score recipes based on how close they are to ideal nutrition
    const scored = available.map(recipe => {
        const nutrition = recipe.nutrition || {};
        
        // Calculate deviation from ideal (lower is better)
        const proteinScore = Math.abs((nutrition.protein || 0) - target.protein) / target.protein;
        const calorieScore = Math.abs((nutrition.calories || 0) - target.calories) / target.calories;
        const carbScore = Math.abs((nutrition.carbs || 0) - target.carbs) / target.carbs;
        const fatScore = Math.abs((nutrition.fat || 0) - target.fat) / target.fat;
        
        // Combined score (lower is better)
        const totalScore = proteinScore + calorieScore + carbScore + fatScore;
        
        return { recipe, score: totalScore };
    });
    
    // Sort by score (best first)
    scored.sort((a, b) => a.score - b.score);
    
    // Return one of the top 3 for variety
    const topBalanced = scored.slice(0, 3);
    return topBalanced[Math.floor(Math.random() * topBalanced.length)].recipe;
}

// AI Mode: Maximum Variety - Ensure diverse selection
function selectMaxVariety(recipes, usedRecipes) {
    const available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) {
        // If all recipes used, pick least recently used
        usedRecipes.clear();
        return recipes[Math.floor(Math.random() * recipes.length)];
    }
    
    // Prioritize recipes with different tags/ingredients
    const unusedTags = new Set();
    available.forEach(r => {
        if (r.tags) {
            r.tags.split(',').forEach(tag => unusedTags.add(tag.trim()));
        }
    });
    
    // Random selection from available
    return available[Math.floor(Math.random() * available.length)];
}

// AI Mode: Seasonal - Prefer seasonal ingredients
function selectSeasonal(recipes, usedRecipes) {
    const available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) return recipes[0];
    
    // Current month (1-12)
    const currentMonth = new Date().getMonth() + 1;
    
    // Define seasonal preferences
    const seasonalTags = {
        spring: ['Spargel', 'Erdbeeren', 'Spinat', 'Radieschen'],
        summer: ['Tomaten', 'Zucchini', 'Beeren', 'Salat', 'Gurken'],
        autumn: ['Kürbis', 'Äpfel', 'Kohl', 'Pilze', 'Birnen'],
        winter: ['Kohl', 'Wurzelgemüse', 'Lauch', 'Rosenkohl']
    };
    
    let season = 'winter';
    if (currentMonth >= 3 && currentMonth <= 5) season = 'spring';
    else if (currentMonth >= 6 && currentMonth <= 8) season = 'summer';
    else if (currentMonth >= 9 && currentMonth <= 11) season = 'autumn';
    
    const preferredTags = seasonalTags[season];
    
    // Score recipes based on seasonal ingredients
    const scored = available.map(recipe => {
        let score = 0;
        const recipeName = recipe.name.toLowerCase();
        const recipeTags = recipe.tags ? recipe.tags.toLowerCase() : '';
        
        preferredTags.forEach(tag => {
            if (recipeName.includes(tag.toLowerCase()) || recipeTags.includes(tag.toLowerCase())) {
                score += 10;
            }
        });
        
        return { recipe, score };
    });
    
    // Sort by seasonal score
    scored.sort((a, b) => b.score - a.score);
    
    // If no seasonal matches, fall back to random
    if (scored[0].score === 0) {
        return available[Math.floor(Math.random() * available.length)];
    }
    
    // Return one of top seasonal choices
    const topSeasonal = scored.filter(s => s.score > 0).slice(0, 3);
    return topSeasonal[Math.floor(Math.random() * topSeasonal.length)].recipe;
}

// AI Mode: Inventory Based - Use available stock
function selectInventoryBased(recipes, usedRecipes) {
    const available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) return recipes[0];
    
    // Get current inventory levels
    const products = db.data.products || [];
    const recipeIngredients = db.data.recipe_ingredients || [];
    
    // Score recipes based on ingredient availability
    const scored = available.map(recipe => {
        const ingredients = recipeIngredients.filter(ri => ri.recipe_id === recipe.id);
        let availabilityScore = 0;
        let totalIngredients = ingredients.length || 1;
        
        ingredients.forEach(ing => {
            const product = products.find(p => p.id === ing.product_id);
            if (product && product.current_stock > 0) {
                // Higher score for items with more stock
                const stockLevel = product.current_stock / (product.min_stock || 1);
                availabilityScore += stockLevel;
            }
        });
        
        return { 
            recipe, 
            score: availabilityScore / totalIngredients 
        };
    });
    
    // Sort by availability score
    scored.sort((a, b) => b.score - a.score);
    
    // Return one of the top available
    const topAvailable = scored.slice(0, 3);
    return topAvailable[Math.floor(Math.random() * topAvailable.length)].recipe;
}

// Calculate statistics for the generated plan
function calculatePlanStatistics(mealPlan, recipes) {
    let totalCost = 0;
    let totalProtein = 0;
    let totalCalories = 0;
    let mealCount = 0;
    const usedRecipes = new Set();
    
    Object.values(mealPlan).forEach(meal => {
        if (meal && meal.id) {
            const recipe = recipes.find(r => r.id === meal.id);
            if (recipe) {
                totalCost += (recipe.cost_per_portion || 0);
                totalProtein += (recipe.nutrition?.protein || 0);
                totalCalories += (recipe.nutrition?.calories || 0);
                usedRecipes.add(recipe.id);
                mealCount++;
            }
        }
    });
    
    return {
        totalCost: Math.round(totalCost),
        averageCostPerMeal: mealCount > 0 ? (totalCost / mealCount).toFixed(2) : 0,
        averageCostPerPortion: mealCount > 0 ? (totalCost / mealCount).toFixed(2) : 0,
        totalProtein: Math.round(totalProtein),
        totalCalories: Math.round(totalCalories),
        uniqueRecipes: usedRecipes.size,
        totalMeals: mealCount,
        varietyScore: usedRecipes.size / Math.max(mealCount, 1)
    };
}

// Generate success message based on mode and results
function getSuccessMessage(mode, stats) {
    const messages = {
        cost_optimized: `Kostenoptimierter Plan erstellt! Durchschnitt: €${stats.averageCostPerPortion}/Portion`,
        balanced_nutrition: `Ausgewogener Ernährungsplan erstellt! ${Math.round(stats.totalProtein / stats.totalMeals)} g Protein pro Mahlzeit`,
        variety: `Abwechslungsreicher Plan mit ${stats.uniqueRecipes} verschiedenen Gerichten erstellt!`,
        seasonal: `Saisonaler Speiseplan für optimale Frische erstellt!`,
        inventory_based: `Lageroptimierter Plan erstellt - nutzt vorhandene Bestände!`
    };
    
    return messages[mode] || 'Speiseplan erfolgreich generiert!';
}

// Optimize existing meal plan based on mode
function optimizeExistingPlan(currentPlan, recipes, mode) {
    const optimizedPlan = { ...currentPlan };
    const suggestions = [];
    const days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
    const meals = ['breakfast', 'lunch', 'dinner'];
    
    // Analyze current plan
    const currentRecipes = new Map();
    Object.entries(currentPlan).forEach(([slot, meal]) => {
        if (meal && meal.id) {
            const recipe = recipes.find(r => r.id === meal.id);
            if (recipe) {
                currentRecipes.set(slot, recipe);
            }
        }
    });
    
    // Optimization strategies based on mode
    switch (mode) {
        case 'cost_optimized':
            optimizeForCost(optimizedPlan, currentRecipes, recipes, suggestions);
            break;
            
        case 'balanced_nutrition':
            optimizeForNutrition(optimizedPlan, currentRecipes, recipes, suggestions, meals);
            break;
            
        case 'variety':
            optimizeForVariety(optimizedPlan, currentRecipes, recipes, suggestions);
            break;
            
        case 'seasonal':
            optimizeForSeason(optimizedPlan, currentRecipes, recipes, suggestions);
            break;
            
        case 'inventory_based':
            optimizeForInventory(optimizedPlan, currentRecipes, recipes, suggestions);
            break;
    }
    
    return { mealPlan: optimizedPlan, suggestions };
}

// Optimize for cost
function optimizeForCost(plan, currentRecipes, allRecipes, suggestions) {
    const costThreshold = 4.0; // €4 per portion
    
    currentRecipes.forEach((recipe, slot) => {
        if ((recipe.cost_per_portion || 0) > costThreshold) {
            // Find cheaper alternative
            const mealType = slot.split('-')[1];
            const alternatives = allRecipes.filter(r => 
                r.id !== recipe.id &&
                (r.category === mealType || r.category === recipe.category) &&
                (r.cost_per_portion || 0) < (recipe.cost_per_portion || 0)
            );
            
            if (alternatives.length > 0) {
                // Sort by cost
                alternatives.sort((a, b) => (a.cost_per_portion || 0) - (b.cost_per_portion || 0));
                const cheaperRecipe = alternatives[0];
                
                plan[slot] = {
                    id: cheaperRecipe.id,
                    name: cheaperRecipe.name
                };
                
                suggestions.push({
                    slot,
                    reason: `Ersetzt ${recipe.name} (€${recipe.cost_per_portion?.toFixed(2)}) mit ${cheaperRecipe.name} (€${cheaperRecipe.cost_per_portion?.toFixed(2)})`,
                    saving: ((recipe.cost_per_portion || 0) - (cheaperRecipe.cost_per_portion || 0)).toFixed(2)
                });
            }
        }
    });
}

// Optimize for nutrition
function optimizeForNutrition(plan, currentRecipes, allRecipes, suggestions, mealTypes) {
    const nutritionTargets = {
        breakfast: { protein: 15, calories: 400 },
        lunch: { protein: 30, calories: 600 },
        dinner: { protein: 25, calories: 500 }
    };
    
    currentRecipes.forEach((recipe, slot) => {
        const mealType = slot.split('-')[1];
        const target = nutritionTargets[mealType];
        
        if (target && recipe.nutrition) {
            const proteinDiff = Math.abs((recipe.nutrition.protein || 0) - target.protein);
            const calorieDiff = Math.abs((recipe.nutrition.calories || 0) - target.calories);
            
            // If nutrition is far from target, find better alternative
            if (proteinDiff > target.protein * 0.3 || calorieDiff > target.calories * 0.3) {
                const alternatives = allRecipes.filter(r =>
                    r.id !== recipe.id &&
                    (r.category === mealType || r.category === recipe.category) &&
                    r.nutrition
                );
                
                // Score alternatives
                const scored = alternatives.map(alt => {
                    const altProteinDiff = Math.abs((alt.nutrition.protein || 0) - target.protein);
                    const altCalorieDiff = Math.abs((alt.nutrition.calories || 0) - target.calories);
                    const score = altProteinDiff / target.protein + altCalorieDiff / target.calories;
                    return { recipe: alt, score };
                });
                
                scored.sort((a, b) => a.score - b.score);
                
                if (scored.length > 0 && scored[0].score < (proteinDiff / target.protein + calorieDiff / target.calories)) {
                    const betterRecipe = scored[0].recipe;
                    
                    plan[slot] = {
                        id: betterRecipe.id,
                        name: betterRecipe.name
                    };
                    
                    suggestions.push({
                        slot,
                        reason: `Bessere Nährwerte: ${betterRecipe.name} (${betterRecipe.nutrition.protein.toFixed(0)}g Protein, ${betterRecipe.nutrition.calories.toFixed(0)} kcal)`,
                        improvement: 'Näher an Ernährungszielen'
                    });
                }
            }
        }
    });
}

// Optimize for variety
function optimizeForVariety(plan, currentRecipes, allRecipes, suggestions) {
    // Count recipe occurrences
    const recipeCount = new Map();
    currentRecipes.forEach((recipe) => {
        recipeCount.set(recipe.id, (recipeCount.get(recipe.id) || 0) + 1);
    });
    
    // Replace duplicates
    currentRecipes.forEach((recipe, slot) => {
        if ((recipeCount.get(recipe.id) || 0) > 1) {
            const mealType = slot.split('-')[1];
            const alternatives = allRecipes.filter(r =>
                r.id !== recipe.id &&
                (r.category === mealType || r.category === recipe.category) &&
                !Array.from(currentRecipes.values()).some(cr => cr.id === r.id)
            );
            
            if (alternatives.length > 0) {
                const newRecipe = alternatives[Math.floor(Math.random() * Math.min(3, alternatives.length))];
                
                plan[slot] = {
                    id: newRecipe.id,
                    name: newRecipe.name
                };
                
                recipeCount.set(recipe.id, (recipeCount.get(recipe.id) || 1) - 1);
                
                suggestions.push({
                    slot,
                    reason: `Mehr Abwechslung: ${recipe.name} ersetzt durch ${newRecipe.name}`,
                    benefit: 'Reduziert Wiederholungen'
                });
            }
        }
    });
}

// Optimize for season
function optimizeForSeason(plan, currentRecipes, allRecipes, suggestions) {
    const currentMonth = new Date().getMonth() + 1;
    const seasonalIngredients = {
        spring: ['Spargel', 'Erdbeeren', 'Spinat', 'Radieschen'],
        summer: ['Tomaten', 'Zucchini', 'Beeren', 'Salat', 'Gurken'],
        autumn: ['Kürbis', 'Äpfel', 'Kohl', 'Pilze', 'Birnen'],
        winter: ['Kohl', 'Wurzelgemüse', 'Lauch', 'Rosenkohl']
    };
    
    let season = 'winter';
    if (currentMonth >= 3 && currentMonth <= 5) season = 'spring';
    else if (currentMonth >= 6 && currentMonth <= 8) season = 'summer';
    else if (currentMonth >= 9 && currentMonth <= 11) season = 'autumn';
    
    const preferredIngredients = seasonalIngredients[season];
    
    currentRecipes.forEach((recipe, slot) => {
        // Check if recipe is seasonal
        const recipeName = recipe.name.toLowerCase();
        const isCurrentSeasonal = preferredIngredients.some(ing => 
            recipeName.includes(ing.toLowerCase())
        );
        
        if (!isCurrentSeasonal) {
            // Find seasonal alternative
            const mealType = slot.split('-')[1];
            const seasonalAlternatives = allRecipes.filter(r => {
                const rName = r.name.toLowerCase();
                return r.id !== recipe.id &&
                    (r.category === mealType || r.category === recipe.category) &&
                    preferredIngredients.some(ing => rName.includes(ing.toLowerCase()));
            });
            
            if (seasonalAlternatives.length > 0) {
                const seasonalRecipe = seasonalAlternatives[Math.floor(Math.random() * Math.min(3, seasonalAlternatives.length))];
                
                plan[slot] = {
                    id: seasonalRecipe.id,
                    name: seasonalRecipe.name
                };
                
                suggestions.push({
                    slot,
                    reason: `Saisonal: ${seasonalRecipe.name} nutzt ${season}liche Zutaten`,
                    benefit: 'Frischere Zutaten, besserer Geschmack'
                });
            }
        }
    });
}

// Optimize for inventory
function optimizeForInventory(plan, currentRecipes, allRecipes, suggestions) {
    const products = db.data.products || [];
    const recipeIngredients = db.data.recipe_ingredients || [];
    
    currentRecipes.forEach((recipe, slot) => {
        // Check current recipe's inventory requirements
        const ingredients = recipeIngredients.filter(ri => ri.recipe_id === recipe.id);
        let lowStockCount = 0;
        
        ingredients.forEach(ing => {
            const product = products.find(p => p.id === ing.product_id);
            if (product && product.current_stock < product.min_stock) {
                lowStockCount++;
            }
        });
        
        // If many ingredients are low, find alternative with better availability
        if (lowStockCount > ingredients.length * 0.3) {
            const mealType = slot.split('-')[1];
            const alternatives = allRecipes.filter(r =>
                r.id !== recipe.id &&
                (r.category === mealType || r.category === recipe.category)
            );
            
            // Score alternatives by availability
            const scored = alternatives.map(alt => {
                const altIngredients = recipeIngredients.filter(ri => ri.recipe_id === alt.id);
                let availabilityScore = 0;
                
                altIngredients.forEach(ing => {
                    const product = products.find(p => p.id === ing.product_id);
                    if (product && product.current_stock > product.min_stock) {
                        availabilityScore += product.current_stock / product.min_stock;
                    }
                });
                
                return {
                    recipe: alt,
                    score: availabilityScore / Math.max(altIngredients.length, 1)
                };
            });
            
            scored.sort((a, b) => b.score - a.score);
            
            if (scored.length > 0 && scored[0].score > 1.5) {
                const availableRecipe = scored[0].recipe;
                
                plan[slot] = {
                    id: availableRecipe.id,
                    name: availableRecipe.name
                };
                
                suggestions.push({
                    slot,
                    reason: `Bessere Verfügbarkeit: ${availableRecipe.name} nutzt vorhandene Lagerbestände`,
                    benefit: 'Reduziert Bestellbedarf'
                });
            }
        }
    });
}

// Generate optimization message
function getOptimizationMessage(mode, improvements, stats) {
    const messages = {
        cost_optimized: `Plan optimiert! ${improvements.costReduction > 0 ? `${improvements.costReduction}% Kostenersparnis` : 'Bereits kostenoptimal'}`,
        balanced_nutrition: `Ernährung verbessert! ${improvements.nutritionImprovement > 0 ? `+${improvements.nutritionImprovement}% mehr Protein` : 'Bereits gut ausgewogen'}`,
        variety: `Abwechslung erhöht! ${improvements.varietyIncrease > 0 ? `+${improvements.varietyIncrease} neue Gerichte` : 'Bereits sehr abwechslungsreich'}`,
        seasonal: `Saisonalität verbessert! Mehr frische, saisonale Zutaten eingeplant`,
        inventory_based: `Lagernutzung optimiert! Reduzierter Bestellbedarf durch bessere Bestandsnutzung`
    };
    
    return messages[mode] || 'Speiseplan erfolgreich optimiert!';
}

// Mapping of recipes containing specific ingredients
const INGREDIENT_MAPPINGS = {
    schwein: [
        'bratwurst', 'schweinebraten', 'speck', 'leberkäse', 'schinken',
        'hackbraten', 'frikadellen', 'königsberger klopse', 'gyros',
        'reisfleisch', 'bohneneintopf mit speck', 'szegediner', 'currywurst',
        'würstchen', 'erbseneintopf mit würstchen', 'rührei mit speck'
    ],
    rind: [
        'rindergulasch', 'gulaschsuppe', 'hackbraten', 'frikadellen',
        'königsberger klopse', 'szegediner gulasch', 'spaghetti bolognese',
        'rindfleisch', 'rindersteak', 'rinderhack'
    ],
    fleisch: [
        'bratwurst', 'schweinebraten', 'speck', 'leberkäse', 'schinken',
        'hackbraten', 'frikadellen', 'königsberger klopse', 'gyros',
        'reisfleisch', 'bohneneintopf mit speck', 'szegediner', 'currywurst',
        'würstchen', 'rindergulasch', 'gulaschsuppe', 'spaghetti bolognese',
        'hähnchen', 'chicken', 'döner', 'erbseneintopf mit würstchen',
        'rührei mit speck', 'caesar salad mit hähnchen', 'wraps mit hähnchen',
        'lachs', 'seelachs', 'fisch', 'garnelen', 'meeresfrüchte', 'thunfisch'
    ]
};

// Custom AI Mode - User-defined criteria with concrete values
function selectCustomMode(recipes, usedRecipes, mealType, config) {
    console.log(`\n🎯 selectCustomMode called for ${mealType} with ${recipes.length} recipes`);
    console.log('📋 Config received:', JSON.stringify(config, null, 2));
    
    let available = recipes.filter(r => !usedRecipes.has(r.id));
    if (available.length === 0) return recipes[0];
    
    console.log(`📊 Available recipes before filters: ${available.length}`);
    
    // Apply exclusions first
    if (config && config.exclusions) {
        // Ingredient exclusions
        if (config.exclusions.ingredients && config.exclusions.ingredients.length > 0) {
            const beforeCount = available.length;
            available = available.filter(recipe => {
                const recipeName = (recipe.name || '').toLowerCase();
                
                // Check each excluded ingredient
                for (const excluded of config.exclusions.ingredients) {
                    const excludedLower = excluded ? excluded.toLowerCase().trim() : '';
                    
                    // Direct check if recipe name contains the excluded ingredient
                    if (excludedLower && recipeName.includes(excludedLower)) {
                        console.log(`  ❌ Excluding "${recipe.name}" - directly contains "${excluded}"`);
                        return false;
                    }
                    
                    // Check ingredient mappings
                    if (INGREDIENT_MAPPINGS[excludedLower]) {
                        for (const mappedDish of INGREDIENT_MAPPINGS[excludedLower]) {
                            if (recipeName.includes(mappedDish.toLowerCase())) {
                                console.log(`  ❌ Excluding "${recipe.name}" - contains ${excluded} (detected: ${mappedDish})`);
                                return false;
                            }
                        }
                    }
                    
                    // Additional common meat terms check
                    if (excludedLower === 'fleisch' || excludedLower === 'meat') {
                        const meatTerms = ['fleisch', 'wurst', 'schinken', 'speck', 'hack', 'steak', 'schnitzel', 'braten'];
                        for (const term of meatTerms) {
                            if (recipeName.includes(term)) {
                                console.log(`  ❌ Excluding "${recipe.name}" - contains meat term: ${term}`);
                                return false;
                            }
                        }
                    }
                }
                return true;
            });
            console.log(`🚫 Ingredient exclusions: ${beforeCount} → ${available.length} recipes`);
        }
        
        // Category exclusions
        if (config.exclusions.categories && config.exclusions.categories.length > 0) {
            const beforeCount = available.length;
            available = available.filter(recipe => {
                const category = (recipe.category || '').toLowerCase();
                if (config.exclusions.categories.includes(category)) {
                    console.log(`  ❌ Excluding "${recipe.name}" - category "${category}"`);
                    return false;
                }
                return true;
            });
            console.log(`🚫 Category exclusions: ${beforeCount} → ${available.length} recipes`);
        }
        
        // Allergen exclusions
        if (config.exclusions.allergens && config.exclusions.allergens.length > 0) {
            const beforeCount = available.length;
            available = available.filter(recipe => {
                const tags = (recipe.tags || '').toLowerCase();
                for (const allergen of config.exclusions.allergens) {
                    if (allergen && tags.includes(allergen.toLowerCase())) {
                        console.log(`  ❌ Excluding "${recipe.name}" - allergen "${allergen}"`);
                        return false;
                    }
                }
                return true;
            });
            console.log(`🚫 Allergen exclusions: ${beforeCount} → ${available.length} recipes`);
        }
    }
    
    console.log(`✅ After all exclusions: ${available.length} recipes remaining`);
    
    if (available.length === 0) {
        console.log('⚠️ All recipes excluded! Using fallback...');
        return recipes[0];
    }
    
    // Apply preferences and scoring with concrete values
    const scored = available.map(recipe => {
        let score = 100; // Start with base score
        const nutrition = recipe.nutrition || {};
        const cost = recipe.cost_per_portion || 0;
        const prepTime = recipe.prep_time || 30;
        
        // Budget constraints
        if (config.budget) {
            // Hard limit on cost per portion
            if (config.budget.maxCostPerPortion && cost > config.budget.maxCostPerPortion) {
                score -= 50; // Heavy penalty for over-budget
            }
            // Bonus for being under target cost
            if (config.budget.maxCostPerPortion && cost < config.budget.maxCostPerPortion * 0.8) {
                score += 10;
            }
        }
        
        // Nutrition requirements
        if (config.nutrition) {
            // Protein requirement
            if (config.nutrition.minProtein && nutrition.protein < config.nutrition.minProtein) {
                score -= 20;
            }
            // Calorie limits
            if (config.nutrition.maxCalories && nutrition.calories > config.nutrition.maxCalories) {
                score -= 30;
            }
            // Vegetable content bonus
            if (config.nutrition.minVeggiePercent) {
                const veggieScore = recipe.tags?.includes('vegetarisch') || recipe.tags?.includes('vegan') ? 20 : 0;
                score += veggieScore;
            }
            // Salt limits
            if (config.nutrition.maxSaltMg && nutrition.salt > config.nutrition.maxSaltMg) {
                score -= 15;
            }
        }
        
        // Time management
        if (config.timeManagement) {
            // Prep time limits
            if (config.timeManagement.maxPrepTime && prepTime > config.timeManagement.maxPrepTime) {
                score -= 25;
            }
            // Bonus for quick meals
            if (prepTime <= 20) {
                score += 15;
            }
        }
        
        // Variety and cuisine preferences
        if (config.variety) {
            // Cuisine preference bonus
            if (config.variety.cuisinePreferences && config.variety.cuisinePreferences.length > 0) {
                const recipeCuisine = recipe.cuisine?.toLowerCase() || '';
                const recipeTagsLower = recipe.tags?.toLowerCase() || '';
                
                for (const cuisine of config.variety.cuisinePreferences) {
                    if (recipeCuisine.includes(cuisine) || recipeTagsLower.includes(cuisine)) {
                        score += 20;
                        break;
                    }
                }
            }
            
            // Seasonal preference
            if (config.variety.seasonalPreference > 50) {
                const seasonalTags = ['frisch', 'saisonal', 'regional'];
                if (seasonalTags.some(tag => recipe.tags?.toLowerCase().includes(tag))) {
                    score += 15;
                }
            }
        }
        
        return { recipe, score };
    });
    
    // Sort by score (highest first) and add randomness to top choices
    scored.sort((a, b) => b.score - a.score);
    
    // Return from top 3 for some variety
    const topChoices = scored.slice(0, Math.min(3, scored.length));
    const selected = topChoices[Math.floor(Math.random() * topChoices.length)];
    
    return selected.recipe;
}

module.exports = router;