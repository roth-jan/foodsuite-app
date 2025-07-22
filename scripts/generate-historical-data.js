const fs = require('fs');
const path = require('path');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');

// Konfiguration
const START_DATE = moment().subtract(2, 'years');
const END_DATE = moment();
const TENANT_ID = 'demo';

// Realistische Muster
const SEASONAL_FACTORS = {
  winter: { orderVolume: 1.2, priceIncrease: 1.05 },
  spring: { orderVolume: 0.9, priceIncrease: 0.98 },
  summer: { orderVolume: 0.7, priceIncrease: 0.95 },
  autumn: { orderVolume: 1.1, priceIncrease: 1.02 }
};

const WEEKDAY_PATTERNS = {
  1: 0.9,  // Montag
  2: 1.0,  // Dienstag
  3: 1.1,  // Mittwoch
  4: 1.0,  // Donnerstag
  5: 0.8,  // Freitag
  6: 0.3,  // Samstag
  7: 0.2   // Sonntag
};

// Utility Funktionen
function getSeasonalFactor(date) {
  const month = date.month();
  if (month < 3 || month === 11) return SEASONAL_FACTORS.winter;
  if (month < 6) return SEASONAL_FACTORS.spring;
  if (month < 9) return SEASONAL_FACTORS.summer;
  return SEASONAL_FACTORS.autumn;
}

function randomVariation(base, variance = 0.2) {
  return base * (1 + (Math.random() - 0.5) * variance);
}

// Lade existierende Daten
function loadExistingData() {
  const dbPath = path.join(__dirname, '..', 'database.json');
  if (fs.existsSync(dbPath)) {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  }
  throw new Error('Database nicht gefunden. Bitte erst npm run init-db ausführen.');
}

// Generiere historische Bestellungen
function generateHistoricalOrders(db, startDate, endDate) {
  const orders = [];
  const suppliers = db.suppliers[TENANT_ID] || [];
  const products = db.products[TENANT_ID] || [];
  
  let currentDate = moment(startDate);
  let orderNumber = 1000;
  
  while (currentDate.isBefore(endDate)) {
    const dayOfWeek = currentDate.isoWeekday();
    const weekdayFactor = WEEKDAY_PATTERNS[dayOfWeek];
    const seasonalFactor = getSeasonalFactor(currentDate);
    
    // Generiere 0-3 Bestellungen pro Tag basierend auf Mustern
    const ordersPerDay = Math.floor(randomVariation(2 * weekdayFactor * seasonalFactor.orderVolume, 0.5));
    
    for (let i = 0; i < ordersPerDay; i++) {
      const supplier = suppliers[Math.floor(Math.random() * suppliers.length)];
      if (!supplier) continue;
      
      // Wähle 3-15 zufällige Produkte
      const orderProducts = [];
      const productCount = Math.floor(Math.random() * 12) + 3;
      
      for (let j = 0; j < productCount; j++) {
        const product = products[Math.floor(Math.random() * products.length)];
        if (!product) continue;
        
        // Realistische Mengen basierend auf Einheit
        let quantity;
        if (product.unit === 'kg') {
          quantity = Math.floor(randomVariation(25, 0.6));
        } else if (product.unit === 'L') {
          quantity = Math.floor(randomVariation(20, 0.5));
        } else {
          quantity = Math.floor(randomVariation(50, 0.7));
        }
        
        // Preis mit saisonaler Variation
        const basePrice = product.price || 2.5;
        const historicalPrice = basePrice * seasonalFactor.priceIncrease * randomVariation(1, 0.1);
        
        orderProducts.push({
          productId: product.id,
          productName: product.name,
          quantity: quantity,
          unit: product.unit,
          pricePerUnit: parseFloat(historicalPrice.toFixed(2)),
          totalPrice: parseFloat((quantity * historicalPrice).toFixed(2))
        });
      }
      
      const totalAmount = orderProducts.reduce((sum, p) => sum + p.totalPrice, 0);
      
      const order = {
        id: uuidv4(),
        orderNumber: `PO-${orderNumber++}`,
        supplierId: supplier.id,
        supplierName: supplier.name,
        orderDate: currentDate.format('YYYY-MM-DD'),
        deliveryDate: currentDate.clone().add(2, 'days').format('YYYY-MM-DD'),
        status: 'delivered',
        items: orderProducts,
        totalAmount: parseFloat(totalAmount.toFixed(2)),
        notes: `Historische Bestellung - ${currentDate.format('MMMM YYYY')}`,
        createdAt: currentDate.toISOString(),
        updatedAt: currentDate.clone().add(2, 'days').toISOString()
      };
      
      orders.push(order);
    }
    
    currentDate.add(1, 'day');
  }
  
  return orders;
}

// Generiere historische Inventar-Transaktionen
function generateInventoryTransactions(db, orders) {
  const transactions = [];
  const products = db.products[TENANT_ID] || [];
  
  // Für jede Bestellung, erstelle Inventar-Transaktionen
  orders.forEach(order => {
    const orderDate = moment(order.deliveryDate);
    
    // Eingang der Waren
    order.items.forEach(item => {
      transactions.push({
        id: uuidv4(),
        productId: item.productId,
        type: 'in',
        quantity: item.quantity,
        unit: item.unit,
        reference: `Bestellung ${order.orderNumber}`,
        date: orderDate.toISOString(),
        notes: `Wareneingang von ${order.supplierName}`,
        createdAt: orderDate.toISOString()
      });
    });
    
    // Simuliere Verbrauch (60-80% der Waren werden innerhalb einer Woche verbraucht)
    order.items.forEach(item => {
      const consumptionRate = 0.6 + Math.random() * 0.2;
      const consumedQuantity = Math.floor(item.quantity * consumptionRate);
      const daysToConsume = Math.floor(Math.random() * 7) + 1;
      
      transactions.push({
        id: uuidv4(),
        productId: item.productId,
        type: 'out',
        quantity: consumedQuantity,
        unit: item.unit,
        reference: 'Verbrauch Küche',
        date: orderDate.clone().add(daysToConsume, 'days').toISOString(),
        notes: 'Täglicher Verbrauch',
        createdAt: orderDate.clone().add(daysToConsume, 'days').toISOString()
      });
    });
  });
  
  return transactions;
}

// Generiere historische Speisepläne
function generateHistoricalMealPlans(db, startDate, endDate) {
  const mealPlans = [];
  const recipes = db.recipes[TENANT_ID] || [];
  
  if (recipes.length === 0) {
    console.warn('Keine Rezepte gefunden. Überspringe Speiseplan-Generierung.');
    return mealPlans;
  }
  
  let currentWeek = moment(startDate).startOf('isoWeek');
  const endWeek = moment(endDate).endOf('isoWeek');
  
  while (currentWeek.isBefore(endWeek)) {
    const weekNumber = currentWeek.isoWeek();
    const year = currentWeek.year();
    
    // Erstelle Wochenplan
    const weekPlan = {
      monday: { breakfast: null, lunch: null, dinner: null },
      tuesday: { breakfast: null, lunch: null, dinner: null },
      wednesday: { breakfast: null, lunch: null, dinner: null },
      thursday: { breakfast: null, lunch: null, dinner: null },
      friday: { breakfast: null, lunch: null, dinner: null },
      saturday: { breakfast: null, lunch: null, dinner: null },
      sunday: { breakfast: null, lunch: null, dinner: null }
    };
    
    // Fülle Plan mit Rezepten
    const days = Object.keys(weekPlan);
    days.forEach(day => {
      // Frühstück (30% Wahrscheinlichkeit)
      if (Math.random() < 0.3) {
        const breakfast = recipes[Math.floor(Math.random() * recipes.length)];
        weekPlan[day].breakfast = {
          id: breakfast.id,
          name: breakfast.name,
          portionSize: 150,
          totalCost: parseFloat((breakfast.costPerPortion * 150).toFixed(2))
        };
      }
      
      // Mittagessen (90% Wahrscheinlichkeit Mo-Fr, 50% Sa-So)
      const lunchProbability = ['saturday', 'sunday'].includes(day) ? 0.5 : 0.9;
      if (Math.random() < lunchProbability) {
        const lunch = recipes[Math.floor(Math.random() * recipes.length)];
        weekPlan[day].lunch = {
          id: lunch.id,
          name: lunch.name,
          portionSize: 200,
          totalCost: parseFloat((lunch.costPerPortion * 200).toFixed(2))
        };
      }
      
      // Abendessen (70% Wahrscheinlichkeit)
      if (Math.random() < 0.7) {
        const dinner = recipes[Math.floor(Math.random() * recipes.length)];
        weekPlan[day].dinner = {
          id: dinner.id,
          name: dinner.name,
          portionSize: 180,
          totalCost: parseFloat((dinner.costPerPortion * 180).toFixed(2))
        };
      }
    });
    
    const mealPlan = {
      id: uuidv4(),
      weekNumber: weekNumber,
      year: year,
      startDate: currentWeek.format('YYYY-MM-DD'),
      endDate: currentWeek.clone().endOf('isoWeek').format('YYYY-MM-DD'),
      meals: weekPlan,
      totalCost: calculateWeekCost(weekPlan),
      status: 'completed',
      createdAt: currentWeek.toISOString(),
      updatedAt: currentWeek.clone().add(7, 'days').toISOString(),
      createdBy: 'system',
      notes: `Historischer Speiseplan KW ${weekNumber}/${year}`
    };
    
    mealPlans.push(mealPlan);
    currentWeek.add(1, 'week');
  }
  
  return mealPlans;
}

function calculateWeekCost(weekPlan) {
  let total = 0;
  Object.values(weekPlan).forEach(day => {
    if (day.breakfast) total += day.breakfast.totalCost;
    if (day.lunch) total += day.lunch.totalCost;
    if (day.dinner) total += day.dinner.totalCost;
  });
  return parseFloat(total.toFixed(2));
}

// Generiere Preisentwicklung für Produkte
function generatePriceHistory(db, startDate, endDate) {
  const priceHistory = [];
  const products = db.products[TENANT_ID] || [];
  
  products.forEach(product => {
    let currentDate = moment(startDate);
    let currentPrice = product.price || 2.5;
    
    while (currentDate.isBefore(endDate)) {
      // Preisänderung alle 1-3 Monate
      if (Math.random() < 0.3) {
        const seasonalFactor = getSeasonalFactor(currentDate);
        const priceChange = randomVariation(1, 0.15) * seasonalFactor.priceIncrease;
        currentPrice = currentPrice * priceChange;
        
        priceHistory.push({
          id: uuidv4(),
          productId: product.id,
          productName: product.name,
          oldPrice: parseFloat((currentPrice / priceChange).toFixed(2)),
          newPrice: parseFloat(currentPrice.toFixed(2)),
          changeDate: currentDate.format('YYYY-MM-DD'),
          changeReason: 'Marktanpassung',
          supplierId: product.supplierId,
          createdAt: currentDate.toISOString()
        });
      }
      
      currentDate.add(1, 'month');
    }
  });
  
  return priceHistory;
}

// Hauptfunktion
async function generateHistoricalData() {
  console.log('Starte Generierung historischer Daten für 2 Jahre...');
  
  try {
    // Lade existierende Datenbank
    const db = loadExistingData();
    
    // Generiere historische Daten
    console.log('Generiere Bestellungen...');
    const historicalOrders = generateHistoricalOrders(db, START_DATE, END_DATE);
    console.log(`${historicalOrders.length} Bestellungen generiert`);
    
    console.log('Generiere Inventar-Transaktionen...');
    const inventoryTransactions = generateInventoryTransactions(db, historicalOrders);
    console.log(`${inventoryTransactions.length} Transaktionen generiert`);
    
    console.log('Generiere Speisepläne...');
    const mealPlans = generateHistoricalMealPlans(db, START_DATE, END_DATE);
    console.log(`${mealPlans.length} Speisepläne generiert`);
    
    console.log('Generiere Preisentwicklung...');
    const priceHistory = generatePriceHistory(db, START_DATE, END_DATE);
    console.log(`${priceHistory.length} Preisänderungen generiert`);
    
    // Füge historische Daten zur Datenbank hinzu
    if (!db.orders) db.orders = {};
    if (!db.orders[TENANT_ID]) db.orders[TENANT_ID] = [];
    db.orders[TENANT_ID] = [...historicalOrders, ...db.orders[TENANT_ID]];
    
    if (!db.inventory) db.inventory = {};
    if (!db.inventory[TENANT_ID]) db.inventory[TENANT_ID] = { transactions: [] };
    db.inventory[TENANT_ID].transactions = [...inventoryTransactions, ...db.inventory[TENANT_ID].transactions];
    
    if (!db.mealplans) db.mealplans = {};
    if (!db.mealplans[TENANT_ID]) db.mealplans[TENANT_ID] = [];
    db.mealplans[TENANT_ID] = [...mealPlans, ...db.mealplans[TENANT_ID]];
    
    if (!db.priceHistory) db.priceHistory = {};
    if (!db.priceHistory[TENANT_ID]) db.priceHistory[TENANT_ID] = [];
    db.priceHistory[TENANT_ID] = priceHistory;
    
    // Speichere aktualisierte Datenbank
    const dbPath = path.join(__dirname, '..', 'database.json');
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
    
    console.log('\n✅ Historische Daten erfolgreich generiert!');
    console.log('\nZusammenfassung:');
    console.log(`- ${historicalOrders.length} Bestellungen über 2 Jahre`);
    console.log(`- ${inventoryTransactions.length} Inventar-Transaktionen`);
    console.log(`- ${mealPlans.length} Wochen-Speisepläne`);
    console.log(`- ${priceHistory.length} dokumentierte Preisänderungen`);
    console.log('\nDas System sieht jetzt aus wie eine etablierte Installation!');
    
  } catch (error) {
    console.error('Fehler bei der Generierung:', error);
    process.exit(1);
  }
}

// Ausführen
generateHistoricalData();