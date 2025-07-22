// Authentication and Authorization Middleware for FoodSuite
const { verifyAccessToken, hasPermission, hasAllPermissions } = require('../utils/auth');
const db = require('../database/db-memory');

// Authentication middleware - verifies JWT token
function authenticate(req, res, next) {
    try {
        // Get token from Authorization header
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'No authentication token provided',
                code: 'NO_TOKEN'
            });
        }
        
        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        
        try {
            // Verify token
            const decoded = verifyAccessToken(token);
            
            // Check if user still exists and is active
            const user = db.query('users')
                .where('id', decoded.id)
                .where('tenant_id', decoded.tenant_id)
                .where('is_active', true)
                .where('is_locked', false)
                .first();
            
            if (!user) {
                return res.status(401).json({
                    error: 'User account not found or inactive',
                    code: 'USER_INACTIVE'
                });
            }
            
            // Get user's permissions
            const rolePermissions = db.query('role_permissions')
                .where('role_id', user.role_id)
                .get();
            
            const permissionIds = rolePermissions.map(rp => rp.permission_id);
            const permissions = db.query('permissions')
                .whereIn('id', permissionIds)
                .get();
            
            // Attach user and permissions to request
            req.user = {
                ...decoded,
                permissions
            };
            
            // Update last activity
            db.query('user_sessions')
                .where('user_id', user.id)
                .where('is_active', true)
                .update({ last_activity: new Date().toISOString() });
            
            next();
        } catch (error) {
            if (error.message === 'TOKEN_EXPIRED') {
                return res.status(401).json({
                    error: 'Authentication token has expired',
                    code: 'TOKEN_EXPIRED'
                });
            } else if (error.message === 'INVALID_TOKEN') {
                return res.status(401).json({
                    error: 'Invalid authentication token',
                    code: 'INVALID_TOKEN'
                });
            }
            throw error;
        }
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(500).json({
            error: 'Authentication failed',
            code: 'AUTH_ERROR'
        });
    }
}

// Authorization middleware - checks specific permissions
function authorize(resource, action) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'NOT_AUTHENTICATED'
            });
        }
        
        // Check if user has the required permission
        if (!hasPermission(req.user.permissions, resource, action)) {
            return res.status(403).json({
                error: `Insufficient permissions for ${action} on ${resource}`,
                code: 'INSUFFICIENT_PERMISSIONS',
                required: { resource, action }
            });
        }
        
        next();
    };
}

// Multiple permissions check - requires all permissions
function authorizeAll(permissions) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'NOT_AUTHENTICATED'
            });
        }
        
        if (!hasAllPermissions(req.user.permissions, permissions)) {
            return res.status(403).json({
                error: 'Insufficient permissions',
                code: 'INSUFFICIENT_PERMISSIONS',
                required: permissions
            });
        }
        
        next();
    };
}

// Role-based authorization
function requireRole(minLevel) {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                code: 'NOT_AUTHENTICATED'
            });
        }
        
        const userRole = db.query('roles')
            .where('id', req.user.role_id)
            .first();
        
        if (!userRole || userRole.level > minLevel) {
            return res.status(403).json({
                error: 'Insufficient role level',
                code: 'INSUFFICIENT_ROLE',
                required_level: minLevel,
                user_level: userRole ? userRole.level : null
            });
        }
        
        next();
    };
}

// Tenant isolation middleware
function validateTenant(req, res, next) {
    const tenantId = req.headers['x-tenant-id'] || req.user?.tenant_id;
    
    if (!tenantId) {
        return res.status(400).json({
            error: 'Tenant ID required',
            code: 'NO_TENANT'
        });
    }
    
    // For authenticated requests, ensure tenant matches
    if (req.user && req.user.tenant_id !== tenantId) {
        return res.status(403).json({
            error: 'Tenant mismatch',
            code: 'TENANT_MISMATCH'
        });
    }
    
    req.tenantId = tenantId;
    next();
}

// Rate limiting for authentication endpoints
const loginAttempts = new Map();

function rateLimitLogin(req, res, next) {
    const identifier = req.body.username || req.ip;
    const key = `${req.tenantId}:${identifier}`;
    
    const attempts = loginAttempts.get(key) || { count: 0, resetAt: Date.now() + 900000 }; // 15 minutes
    
    if (Date.now() > attempts.resetAt) {
        attempts.count = 0;
        attempts.resetAt = Date.now() + 900000;
    }
    
    if (attempts.count >= 5) {
        const remainingTime = Math.ceil((attempts.resetAt - Date.now()) / 1000);
        return res.status(429).json({
            error: 'Too many login attempts',
            code: 'RATE_LIMITED',
            retry_after: remainingTime
        });
    }
    
    attempts.count++;
    loginAttempts.set(key, attempts);
    
    req.loginAttempts = attempts.count;
    next();
}

// Audit logging middleware
function auditLog(resource, action) {
    return async (req, res, next) => {
        // Store original send function
        const originalSend = res.send;
        
        // Override send to capture response
        res.send = function(data) {
            res.locals.responseData = data;
            originalSend.call(res, data);
        };
        
        // Continue with request
        next();
        
        // Log after response
        res.on('finish', () => {
            if (req.user && res.statusCode < 400) {
                const logEntry = {
                    tenant_id: req.tenantId,
                    user_id: req.user.id,
                    action: `${req.method} ${action}`,
                    resource: resource,
                    resource_id: req.params.id || null,
                    ip_address: req.ip,
                    user_agent: req.headers['user-agent'],
                    created_at: new Date().toISOString()
                };
                
                // Add request/response data for important operations
                if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
                    logEntry.old_values = req.body;
                    logEntry.new_values = res.locals.responseData;
                }
                
                db.insert('audit_log', logEntry);
            }
        });
    };
}

// Optional authentication - doesn't fail if no token
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // No token provided, continue without user
        return next();
    }
    
    // If token is provided, validate it
    authenticate(req, res, next);
}

module.exports = {
    authenticate,
    authorize,
    authorizeAll,
    requireRole,
    validateTenant,
    rateLimitLogin,
    auditLog,
    optionalAuth
};