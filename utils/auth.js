// Authentication utilities for FoodSuite
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Configuration
const config = {
    jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key-change-in-production',
    jwtExpiry: '15m', // Access token expires in 15 minutes
    refreshExpiry: '7d', // Refresh token expires in 7 days
    saltRounds: 10,
    maxLoginAttempts: 5,
    lockoutDuration: 30 * 60 * 1000 // 30 minutes in milliseconds
};

// Password hashing
async function hashPassword(password) {
    return bcrypt.hash(password, config.saltRounds);
}

async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

// JWT token generation
function generateAccessToken(user) {
    const payload = {
        id: user.id,
        username: user.username,
        email: user.email,
        tenant_id: user.tenant_id,
        role_id: user.role_id,
        permissions: user.permissions || []
    };

    return jwt.sign(payload, config.jwtSecret, {
        expiresIn: config.jwtExpiry,
        issuer: 'foodsuite',
        audience: user.tenant_id
    });
}

function generateRefreshToken(user) {
    const payload = {
        id: user.id,
        tenant_id: user.tenant_id,
        type: 'refresh'
    };

    return jwt.sign(payload, config.jwtRefreshSecret, {
        expiresIn: config.refreshExpiry,
        issuer: 'foodsuite',
        audience: user.tenant_id
    });
}

// Token verification
function verifyAccessToken(token) {
    try {
        return jwt.verify(token, config.jwtSecret, {
            issuer: 'foodsuite'
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('TOKEN_EXPIRED');
        } else if (error.name === 'JsonWebTokenError') {
            throw new Error('INVALID_TOKEN');
        }
        throw error;
    }
}

function verifyRefreshToken(token) {
    try {
        const decoded = jwt.verify(token, config.jwtRefreshSecret, {
            issuer: 'foodsuite'
        });
        
        if (decoded.type !== 'refresh') {
            throw new Error('INVALID_TOKEN_TYPE');
        }
        
        return decoded;
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('REFRESH_TOKEN_EXPIRED');
        } else if (error.name === 'JsonWebTokenError') {
            throw new Error('INVALID_REFRESH_TOKEN');
        }
        throw error;
    }
}

// Session token generation
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Password validation
function validatePassword(password) {
    const errors = [];
    
    if (password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return {
        valid: errors.length === 0,
        errors
    };
}

// Generate secure random password
function generateSecurePassword(length = 12) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
    let password = '';
    
    // Ensure at least one of each required character type
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
    password += '0123456789'[Math.floor(Math.random() * 10)];
    password += '!@#$%^&*()'[Math.floor(Math.random() * 10)];
    
    // Fill the rest randomly
    for (let i = 4; i < length; i++) {
        password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Check if user account is locked
function isAccountLocked(user) {
    if (!user.is_locked) return false;
    
    if (user.locked_until) {
        const now = new Date();
        const lockedUntil = new Date(user.locked_until);
        
        if (now > lockedUntil) {
            // Lock period has expired
            return false;
        }
    }
    
    return true;
}

// Calculate lockout time after failed attempts
function calculateLockoutTime(failedAttempts) {
    if (failedAttempts < config.maxLoginAttempts) {
        return null;
    }
    
    const now = new Date();
    return new Date(now.getTime() + config.lockoutDuration);
}

// Permission checking
function hasPermission(userPermissions, resource, action) {
    return userPermissions.some(permission => 
        permission.resource === resource && permission.action === action
    );
}

function hasAnyPermission(userPermissions, requiredPermissions) {
    return requiredPermissions.some(required =>
        hasPermission(userPermissions, required.resource, required.action)
    );
}

function hasAllPermissions(userPermissions, requiredPermissions) {
    return requiredPermissions.every(required =>
        hasPermission(userPermissions, required.resource, required.action)
    );
}

// Two-factor authentication
function generateTwoFactorSecret() {
    return crypto.randomBytes(20).toString('hex');
}

function generateTwoFactorCode(secret) {
    const time = Math.floor(Date.now() / 30000);
    const hmac = crypto.createHmac('sha1', secret);
    hmac.update(Buffer.from(time.toString(), 'hex'));
    const hash = hmac.digest('hex');
    const offset = parseInt(hash.slice(-1), 16);
    const code = parseInt(hash.slice(offset, offset + 8), 16) & 0x7fffffff;
    return (code % 1000000).toString().padStart(6, '0');
}

function verifyTwoFactorCode(secret, code, window = 1) {
    const currentTime = Math.floor(Date.now() / 30000);
    
    for (let i = -window; i <= window; i++) {
        const time = currentTime + i;
        const expectedCode = generateTwoFactorCode(secret, time);
        if (code === expectedCode) {
            return true;
        }
    }
    
    return false;
}

module.exports = {
    config,
    hashPassword,
    verifyPassword,
    generateAccessToken,
    generateRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    generateSessionToken,
    validatePassword,
    generateSecurePassword,
    isAccountLocked,
    calculateLockoutTime,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    generateTwoFactorSecret,
    generateTwoFactorCode,
    verifyTwoFactorCode
};