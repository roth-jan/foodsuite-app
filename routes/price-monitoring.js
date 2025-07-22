const express = require('express');
const router = express.Router();

// Price monitoring data structures
const priceHistory = new Map(); // productId -> Array of price records
const priceAlerts = new Map(); // alertId -> alert configuration
const supplierPrices = new Map(); // productId -> Map(supplierId -> price info)

// Initialize with some sample data
function initializePriceMonitoring() {
    // Sample price history for demonstration
    const sampleHistory = [
        { productId: 1, date: new Date('2024-01-01'), price: 2.30, supplierId: 1, supplierName: 'Metro' },
        { productId: 1, date: new Date('2024-02-01'), price: 2.50, supplierId: 1, supplierName: 'Metro' },
        { productId: 1, date: new Date('2024-03-01'), price: 2.45, supplierId: 1, supplierName: 'Metro' }
    ];
    
    sampleHistory.forEach(record => {
        if (!priceHistory.has(record.productId)) {
            priceHistory.set(record.productId, []);
        }
        priceHistory.get(record.productId).push(record);
    });
}

// Get price history for a product
router.get('/history/:productId', (req, res) => {
    const { productId } = req.params;
    const history = priceHistory.get(parseInt(productId)) || [];
    
    // Calculate price changes
    const enrichedHistory = history.map((record, index) => {
        if (index > 0) {
            const previousPrice = history[index - 1].price;
            record.change = ((record.price - previousPrice) / previousPrice * 100).toFixed(2);
            record.changeAbsolute = (record.price - previousPrice).toFixed(2);
        }
        return record;
    });
    
    res.json({
        productId,
        history: enrichedHistory,
        currentPrice: enrichedHistory[enrichedHistory.length - 1]?.price || 0,
        averagePrice: enrichedHistory.reduce((sum, r) => sum + r.price, 0) / enrichedHistory.length || 0,
        trend: calculateTrend(enrichedHistory)
    });
});

// Record a new price (automatically track price changes)
router.post('/record-price', (req, res) => {
    const { productId, price, supplierId, supplierName } = req.body;
    
    if (!productId || !price || !supplierId) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const record = {
        productId: parseInt(productId),
        price: parseFloat(price),
        supplierId: parseInt(supplierId),
        supplierName,
        date: new Date(),
        timestamp: Date.now()
    };
    
    // Add to history
    if (!priceHistory.has(record.productId)) {
        priceHistory.set(record.productId, []);
    }
    const history = priceHistory.get(record.productId);
    
    // Check for price change
    const lastPrice = history[history.length - 1]?.price;
    if (lastPrice && lastPrice !== record.price) {
        const changePercent = ((record.price - lastPrice) / lastPrice * 100).toFixed(2);
        record.change = changePercent;
        record.changeAbsolute = (record.price - lastPrice).toFixed(2);
        
        // Trigger alerts if needed
        checkPriceAlerts(record.productId, record.price, lastPrice, changePercent);
    }
    
    history.push(record);
    
    // Update supplier prices
    if (!supplierPrices.has(record.productId)) {
        supplierPrices.set(record.productId, new Map());
    }
    supplierPrices.get(record.productId).set(record.supplierId, {
        price: record.price,
        supplierName: record.supplierName,
        lastUpdate: record.date
    });
    
    res.json({ 
        success: true, 
        record,
        alertsTriggered: record.alertsTriggered || []
    });
});

// Get price comparison between suppliers
router.get('/compare/:productId', (req, res) => {
    const { productId } = req.params;
    const suppliers = supplierPrices.get(parseInt(productId));
    
    if (!suppliers || suppliers.size === 0) {
        return res.json({ productId, suppliers: [], message: 'No supplier prices available' });
    }
    
    const comparison = Array.from(suppliers.entries()).map(([supplierId, info]) => ({
        supplierId,
        ...info,
        deviation: 0 // Will be calculated below
    }));
    
    // Calculate average and deviations
    const avgPrice = comparison.reduce((sum, s) => sum + s.price, 0) / comparison.length;
    comparison.forEach(s => {
        s.deviation = ((s.price - avgPrice) / avgPrice * 100).toFixed(2);
    });
    
    // Sort by price
    comparison.sort((a, b) => a.price - b.price);
    
    res.json({
        productId,
        suppliers: comparison,
        bestPrice: comparison[0],
        worstPrice: comparison[comparison.length - 1],
        averagePrice: avgPrice.toFixed(2),
        potentialSaving: ((comparison[comparison.length - 1].price - comparison[0].price) * 100).toFixed(2)
    });
});

// Configure price alerts
router.post('/alerts', (req, res) => {
    const { productId, type, threshold, email, name } = req.body;
    
    const alertId = Date.now().toString();
    const alert = {
        id: alertId,
        productId: parseInt(productId),
        type, // 'increase', 'decrease', 'threshold_above', 'threshold_below'
        threshold: parseFloat(threshold),
        email,
        name,
        active: true,
        created: new Date(),
        triggered: 0
    };
    
    priceAlerts.set(alertId, alert);
    
    res.json({ success: true, alert });
});

// Get all alerts
router.get('/alerts', (req, res) => {
    const alerts = Array.from(priceAlerts.values());
    res.json(alerts);
});

// Get price trends
router.get('/trends', (req, res) => {
    const { days = 30 } = req.query;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));
    
    const trends = [];
    
    priceHistory.forEach((history, productId) => {
        const recentHistory = history.filter(h => h.date >= cutoffDate);
        if (recentHistory.length >= 2) {
            const firstPrice = recentHistory[0].price;
            const lastPrice = recentHistory[recentHistory.length - 1].price;
            const change = ((lastPrice - firstPrice) / firstPrice * 100).toFixed(2);
            
            trends.push({
                productId,
                productName: `Product ${productId}`, // In real app, would look up product name
                firstPrice,
                lastPrice,
                change: parseFloat(change),
                trend: change > 5 ? 'rising' : change < -5 ? 'falling' : 'stable',
                dataPoints: recentHistory.length
            });
        }
    });
    
    // Sort by biggest changes
    trends.sort((a, b) => Math.abs(b.change) - Math.abs(a.change));
    
    res.json({
        period: `${days} days`,
        trends,
        summary: {
            rising: trends.filter(t => t.trend === 'rising').length,
            falling: trends.filter(t => t.trend === 'falling').length,
            stable: trends.filter(t => t.trend === 'stable').length
        }
    });
});

// Helper functions
function calculateTrend(history) {
    if (history.length < 2) return 'insufficient_data';
    
    const recent = history.slice(-5); // Last 5 records
    let increases = 0;
    let decreases = 0;
    
    for (let i = 1; i < recent.length; i++) {
        if (recent[i].price > recent[i-1].price) increases++;
        else if (recent[i].price < recent[i-1].price) decreases++;
    }
    
    if (increases > decreases * 2) return 'strong_upward';
    if (increases > decreases) return 'upward';
    if (decreases > increases * 2) return 'strong_downward';
    if (decreases > increases) return 'downward';
    return 'stable';
}

function checkPriceAlerts(productId, newPrice, oldPrice, changePercent) {
    const triggeredAlerts = [];
    
    priceAlerts.forEach(alert => {
        if (alert.productId === productId && alert.active) {
            let triggered = false;
            
            switch (alert.type) {
                case 'increase':
                    if (changePercent > alert.threshold) triggered = true;
                    break;
                case 'decrease':
                    if (changePercent < -alert.threshold) triggered = true;
                    break;
                case 'threshold_above':
                    if (newPrice > alert.threshold) triggered = true;
                    break;
                case 'threshold_below':
                    if (newPrice < alert.threshold) triggered = true;
                    break;
            }
            
            if (triggered) {
                alert.triggered++;
                alert.lastTriggered = new Date();
                triggeredAlerts.push({
                    ...alert,
                    oldPrice,
                    newPrice,
                    changePercent
                });
                
                // In production, would send email/notification here
                console.log(`🚨 Price Alert: ${alert.name} - Product ${productId} price changed from ${oldPrice} to ${newPrice} (${changePercent}%)`);
            }
        }
    });
    
    return triggeredAlerts;
}

// Initialize on load
initializePriceMonitoring();

module.exports = router;