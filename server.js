require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const roleRoutes = require('./routes/roles');
const productRoutes = require('./routes/products');
const supplierRoutes = require('./routes/suppliers');
const orderRoutes = require('./routes/orders');
const recipeRoutes = require('./routes/recipes');
const inventoryRoutes = require('./routes/inventory');
const mealPlanRoutes = require('./routes/mealplans');
const analyticsRoutes = require('./routes/analytics');
const tenantRoutes = require('./routes/tenants');

// Import database
const dbType = process.env.DB_TYPE || 'memory';
const db = dbType === 'postgres' ? require('./database/postgres-adapter') : require('./database/db-memory');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // limit each IP to 1000 requests per windowMs (increased for testing)
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// app.use(limiter); // Temporarily disabled for testing

// CORS configuration
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or file:// or Postman)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = process.env.NODE_ENV === 'production' ? 
            ['https://yourdomain.com'] : 
            ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080', 'null'];
            
        if (allowedOrigins.indexOf(origin) !== -1 || origin.startsWith('file://')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'x-tenant-id']
}));

// Health check endpoints (before authentication)
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        version: '1.0.0'
    });
});

app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        service: 'foodsuite-api',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// General middleware
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'foodsuite-complete-app.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Tenant middleware - extract tenant from header or default to 'demo'
app.use('/api', (req, res, next) => {
    req.tenantId = req.headers['x-tenant-id'] || 'demo';
    next();
});

// API Routes
// Auth routes (no authentication required for login)
app.use('/api/auth', authRoutes);

// Protected routes
app.use('/api/users', userRoutes);
app.use('/api/roles', roleRoutes);
app.use('/api/products', productRoutes);
app.use('/api/suppliers', supplierRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/recipes', recipeRoutes);
app.use('/api/inventory', inventoryRoutes);
app.use('/api/mealplans', mealPlanRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/tenants', tenantRoutes);
app.use('/api/ai', require('./routes/ai'));
app.use('/api/price-monitoring', require('./routes/price-monitoring'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation Error',
            message: err.message,
            details: err.details
        });
    }
    
    if (err.name === 'UnauthorizedError') {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Access token is missing or invalid'
        });
    }
    
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'production' ? 
            'Something went wrong!' : 
            err.message
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found'
    });
});

// Initialize database and start server
async function startServer() {
    try {
        // Initialize database
        await db.initialize();
        console.log('✅ Database initialized successfully');
        
        // Start server
        app.listen(PORT, () => {
            console.log(`🚀 FoodSuite Backend Server running on port ${PORT}`);
            console.log(`📱 Frontend: http://localhost:${PORT}`);
            console.log(`🔧 API Base: http://localhost:${PORT}/api`);
            console.log(`❤️  Health Check: http://localhost:${PORT}/api/health`);
            console.log(`🏢 Environment: ${process.env.NODE_ENV || 'development'}`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔄 SIGTERM received, shutting down gracefully');
    db.close();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🔄 SIGINT received, shutting down gracefully');
    db.close();
    process.exit(0);
});

startServer();

module.exports = app;