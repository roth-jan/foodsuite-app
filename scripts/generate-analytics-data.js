const fs = require('fs');
const path = require('path');

// Analytics-Daten Generator
function generateAnalyticsData() {
    const analytics = {
        dashboardMetrics: generateDashboardMetrics(),
        costAnalysis: generateCostAnalysis(),
        consumptionPatterns: generateConsumptionPatterns(),
        supplierPerformance: generateSupplierPerformance(),
        wasteAnalysis: generateWasteAnalysis(),
        nutritionTracking: generateNutritionTracking()
    };
    
    return analytics;
}

// Dashboard-Metriken (Übersicht)
function generateDashboardMetrics() {
    const months = [];
    const currentDate = new Date();
    
    for (let i = 23; i >= 0; i--) {
        const date = new Date(currentDate);
        date.setMonth(date.getMonth() - i);
        
        const month = {
            month: date.toISOString().slice(0, 7),
            totalCost: Math.floor(15000 + Math.random() * 5000),
            mealsServed: Math.floor(8000 + Math.random() * 2000),
            costPerMeal: 0,
            inventoryValue: Math.floor(25000 + Math.random() * 10000),
            activeSuppliers: Math.floor(8 + Math.random() * 4),
            recipeCount: Math.floor(120 + i * 2),
            avgDeliveryTime: Math.floor(24 + Math.random() * 12),
            stockoutIncidents: Math.floor(Math.random() * 5)
        };
        
        month.costPerMeal = (month.totalCost / month.mealsServed).toFixed(2);
        months.push(month);
    }
    
    return months;
}

// Kostenanalyse nach Kategorien
function generateCostAnalysis() {
    const categories = [
        { name: 'Fleisch & Fisch', percentage: 35, trend: 'up' },
        { name: 'Gemüse & Obst', percentage: 25, trend: 'stable' },
        { name: 'Milchprodukte', percentage: 15, trend: 'up' },
        { name: 'Getreideprodukte', percentage: 10, trend: 'down' },
        { name: 'Gewürze & Zutaten', percentage: 8, trend: 'stable' },
        { name: 'Getränke', percentage: 7, trend: 'up' }
    ];
    
    const monthlyBreakdown = [];
    const currentDate = new Date();
    
    for (let i = 11; i >= 0; i--) {
        const date = new Date(currentDate);
        date.setMonth(date.getMonth() - i);
        const monthData = { month: date.toISOString().slice(0, 7), categories: {} };
        
        let totalCost = 0;
        categories.forEach(cat => {
            const baseCost = cat.percentage * 150; // Base cost
            const variation = Math.random() * 20 - 10; // ±10% variation
            const seasonalFactor = getSeason(date) === 'Sommer' && cat.name === 'Gemüse & Obst' ? 0.8 : 1;
            const cost = Math.floor(baseCost * (1 + variation/100) * seasonalFactor);
            monthData.categories[cat.name] = cost;
            totalCost += cost;
        });
        
        monthData.totalCost = totalCost;
        monthlyBreakdown.push(monthData);
    }
    
    return {
        currentDistribution: categories,
        monthlyBreakdown: monthlyBreakdown,
        yearOverYear: {
            currentYear: Math.floor(180000 + Math.random() * 20000),
            previousYear: Math.floor(175000 + Math.random() * 20000),
            change: '+2.8%'
        }
    };
}

// Verbrauchsmuster
function generateConsumptionPatterns() {
    const patterns = {
        weeklyPattern: [
            { day: 'Montag', meals: 450, peakHour: '12:30' },
            { day: 'Dienstag', meals: 480, peakHour: '12:30' },
            { day: 'Mittwoch', meals: 470, peakHour: '12:45' },
            { day: 'Donnerstag', meals: 490, peakHour: '12:30' },
            { day: 'Freitag', meals: 420, peakHour: '12:15' },
            { day: 'Samstag', meals: 150, peakHour: '12:00' },
            { day: 'Sonntag', meals: 100, peakHour: '12:00' }
        ],
        seasonalTrends: {
            spring: { avgMealsPerDay: 380, popularCategories: ['Salate', 'Leichte Gerichte'] },
            summer: { avgMealsPerDay: 350, popularCategories: ['Salate', 'Kalte Speisen'] },
            autumn: { avgMealsPerDay: 420, popularCategories: ['Eintöpfe', 'Deftige Gerichte'] },
            winter: { avgMealsPerDay: 450, popularCategories: ['Suppen', 'Warme Gerichte'] }
        },
        topDishes: generateTopDishes()
    };
    
    return patterns;
}

// Top-Gerichte basierend auf Beliebtheit
function generateTopDishes() {
    const dishes = [
        { name: 'Spaghetti Bolognese', servings: 2450, rating: 4.5, trend: 'stable' },
        { name: 'Hähnchen-Curry', servings: 2200, rating: 4.3, trend: 'up' },
        { name: 'Gemüselasagne', servings: 1980, rating: 4.2, trend: 'up' },
        { name: 'Fischfilet mit Kartoffeln', servings: 1850, rating: 4.0, trend: 'down' },
        { name: 'Rindergulasch', servings: 1720, rating: 4.4, trend: 'stable' },
        { name: 'Caesar Salad', servings: 1650, rating: 4.1, trend: 'up' },
        { name: 'Schweinebraten', servings: 1500, rating: 3.9, trend: 'down' },
        { name: 'Veggie-Burger', servings: 1450, rating: 4.2, trend: 'up' },
        { name: 'Kürbissuppe', servings: 1200, rating: 4.3, trend: 'seasonal' },
        { name: 'Pasta Primavera', servings: 1100, rating: 4.0, trend: 'stable' }
    ];
    
    return dishes;
}

// Lieferanten-Performance
function generateSupplierPerformance() {
    const suppliers = [
        { 
            name: 'Metro AG', 
            onTimeDelivery: 96.5, 
            qualityScore: 4.8, 
            priceCompetitiveness: 4.2,
            orderVolume: 45000,
            issues: 3
        },
        { 
            name: 'EDEKA Foodservice', 
            onTimeDelivery: 94.2, 
            qualityScore: 4.6, 
            priceCompetitiveness: 4.5,
            orderVolume: 38000,
            issues: 5
        },
        { 
            name: 'Transgourmet', 
            onTimeDelivery: 97.8, 
            qualityScore: 4.7, 
            priceCompetitiveness: 4.0,
            orderVolume: 32000,
            issues: 2
        },
        { 
            name: 'Hoflieferant Schmidt', 
            onTimeDelivery: 92.3, 
            qualityScore: 4.9, 
            priceCompetitiveness: 3.8,
            orderVolume: 18000,
            issues: 4
        },
        { 
            name: 'Bio-Großhandel Weber', 
            onTimeDelivery: 95.5, 
            qualityScore: 4.8, 
            priceCompetitiveness: 3.5,
            orderVolume: 22000,
            issues: 3
        }
    ];
    
    // Performance-Trends über Zeit
    const performanceTrends = [];
    for (let i = 5; i >= 0; i--) {
        const month = new Date();
        month.setMonth(month.getMonth() - i);
        
        performanceTrends.push({
            month: month.toISOString().slice(0, 7),
            avgOnTimeDelivery: 94 + Math.random() * 4,
            avgQualityScore: 4.5 + Math.random() * 0.3,
            totalIssues: Math.floor(10 + Math.random() * 10)
        });
    }
    
    return {
        suppliers: suppliers,
        trends: performanceTrends,
        recommendations: [
            'Metro AG zeigt konstant beste Lieferperformance',
            'Preis-Verhandlungen mit Transgourmet empfohlen',
            'Qualitätsprobleme bei EDEKA Foodservice beobachten'
        ]
    };
}

// Abfall-Analyse
function generateWasteAnalysis() {
    const wasteData = {
        monthlyWaste: [],
        wasteByCategory: [
            { category: 'Überproduktion', percentage: 35, avgKg: 120 },
            { category: 'Verderb', percentage: 25, avgKg: 85 },
            { category: 'Tellerreste', percentage: 30, avgKg: 102 },
            { category: 'Lagerverluste', percentage: 10, avgKg: 34 }
        ],
        reductionTrend: []
    };
    
    // Monatliche Abfalldaten
    for (let i = 11; i >= 0; i--) {
        const month = new Date();
        month.setMonth(month.getMonth() - i);
        
        const baseWaste = 350 - (i * 5); // Abnehmender Trend
        const seasonalFactor = getSeason(month) === 'Sommer' ? 1.2 : 1;
        
        wasteData.monthlyWaste.push({
            month: month.toISOString().slice(0, 7),
            totalKg: Math.floor(baseWaste * seasonalFactor + Math.random() * 50),
            costImpact: Math.floor(baseWaste * 3.5 + Math.random() * 100),
            recyclingRate: 65 + Math.random() * 10
        });
    }
    
    // Reduktionstrend
    const startWaste = 400;
    const currentWaste = 320;
    wasteData.reductionTrend = {
        yearStart: startWaste,
        current: currentWaste,
        reduction: ((startWaste - currentWaste) / startWaste * 100).toFixed(1) + '%',
        targetReduction: '25%',
        onTrack: true
    };
    
    return wasteData;
}

// Ernährungs-Tracking
function generateNutritionTracking() {
    const nutritionData = {
        avgNutritionPerMeal: {
            calories: 650,
            protein: 28,
            carbs: 75,
            fat: 22,
            fiber: 8,
            sodium: 980
        },
        monthlyAverages: [],
        dietaryCompliance: {
            vegetarianOptions: 35,
            veganOptions: 20,
            glutenFreeOptions: 15,
            lowCalorieOptions: 25,
            highProteinOptions: 30
        },
        nutritionGoals: {
            avgCaloriesTarget: 600,
            maxSodiumTarget: 900,
            minFiberTarget: 10,
            status: 'partially met'
        }
    };
    
    // Monatliche Durchschnittswerte
    for (let i = 5; i >= 0; i--) {
        const month = new Date();
        month.setMonth(month.getMonth() - i);
        
        nutritionData.monthlyAverages.push({
            month: month.toISOString().slice(0, 7),
            avgCalories: 640 + Math.floor(Math.random() * 40),
            avgProtein: 26 + Math.floor(Math.random() * 6),
            avgFiber: 7 + Math.random() * 3,
            healthScore: 7.5 + Math.random() * 1.5
        });
    }
    
    return nutritionData;
}

// Hilfsfunktion für Saison
function getSeason(date) {
    const month = date.getMonth();
    if (month >= 2 && month <= 4) return 'Frühling';
    if (month >= 5 && month <= 7) return 'Sommer';
    if (month >= 8 && month <= 10) return 'Herbst';
    return 'Winter';
}

// Haupt-Ausführung
if (require.main === module) {
    console.log('Generiere Analytics-Daten...\n');
    
    const analyticsData = generateAnalyticsData();
    
    // Speichere Daten
    const outputDir = path.join(__dirname, '..', 'data', 'analytics');
    
    // Erstelle Verzeichnis falls nicht vorhanden
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Speichere verschiedene Analytics-Bereiche
    Object.entries(analyticsData).forEach(([key, data]) => {
        const filename = path.join(outputDir, `${key}.json`);
        fs.writeFileSync(filename, JSON.stringify(data, null, 2));
        console.log(`✓ ${key} gespeichert in ${filename}`);
    });
    
    // Erstelle auch eine Gesamt-Datei
    const fullDataFile = path.join(outputDir, 'analytics-complete.json');
    fs.writeFileSync(fullDataFile, JSON.stringify(analyticsData, null, 2));
    
    console.log('\n✅ Analytics-Daten erfolgreich generiert!');
    console.log(`Gesamt-Datei: ${fullDataFile}`);
    
    // Zeige Zusammenfassung
    console.log('\n📊 Analytics-Zusammenfassung:');
    console.log(`- Dashboard-Metriken: ${analyticsData.dashboardMetrics.length} Monate`);
    console.log(`- Kostenanalyse: ${Object.keys(analyticsData.costAnalysis.monthlyBreakdown[0].categories).length} Kategorien`);
    console.log(`- Top-Gerichte: ${analyticsData.consumptionPatterns.topDishes.length} Gerichte`);
    console.log(`- Lieferanten-Performance: ${analyticsData.supplierPerformance.suppliers.length} Lieferanten`);
    console.log(`- Abfall-Tracking: ${analyticsData.wasteAnalysis.monthlyWaste.length} Monate`);
    console.log(`- Ernährungs-Daten: ${analyticsData.nutritionTracking.monthlyAverages.length} Monate`);
}

module.exports = { generateAnalyticsData };