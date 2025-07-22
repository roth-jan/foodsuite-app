// Authentication Routes for FoodSuite
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const {
    hashPassword,
    verifyPassword,
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
    generateSessionToken,
    validatePassword,
    isAccountLocked,
    calculateLockoutTime
} = require('../utils/auth');
const {
    authenticate,
    validateTenant,
    rateLimitLogin
} = require('../middleware/auth-middleware');
const db = require('../database/db-memory');

// Validation schemas
const loginSchema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
    remember_me: Joi.boolean().optional()
});

const registerSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    first_name: Joi.string().required(),
    last_name: Joi.string().required(),
    role_id: Joi.number().optional()
});

const changePasswordSchema = Joi.object({
    current_password: Joi.string().required(),
    new_password: Joi.string().min(8).required()
});

const resetPasswordSchema = Joi.object({
    email: Joi.string().email().required()
});

// Login endpoint
router.post('/login', validateTenant, rateLimitLogin, async (req, res) => {
    try {
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { username, password, remember_me } = value;

        // Find user
        const user = db.query('users')
            .where('username', username)
            .where('tenant_id', req.tenantId)
            .first();

        if (!user) {
            return res.status(401).json({
                error: 'Invalid username or password',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            return res.status(403).json({
                error: 'Account is locked due to too many failed attempts',
                code: 'ACCOUNT_LOCKED',
                locked_until: user.locked_until
            });
        }

        // Verify password
        const validPassword = await verifyPassword(password, user.password_hash);

        if (!validPassword) {
            // Increment failed attempts
            const newAttempts = (user.failed_login_attempts || 0) + 1;
            const lockoutTime = calculateLockoutTime(newAttempts);

            db.query('users')
                .where('id', user.id)
                .update({
                    failed_login_attempts: newAttempts,
                    is_locked: lockoutTime !== null,
                    locked_until: lockoutTime
                });

            return res.status(401).json({
                error: 'Invalid username or password',
                code: 'INVALID_CREDENTIALS',
                attempts_remaining: Math.max(0, 5 - newAttempts)
            });
        }

        // Check if user is active
        if (!user.is_active) {
            return res.status(403).json({
                error: 'Account is inactive',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        // Get user role and permissions
        const role = db.query('roles').where('id', user.role_id).first();
        const rolePermissions = db.query('role_permissions')
            .where('role_id', user.role_id)
            .get();
        
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const permissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        // Generate tokens
        const userWithPermissions = { ...user, permissions };
        const accessToken = generateAccessToken(userWithPermissions);
        const refreshToken = generateRefreshToken(user);
        const sessionToken = generateSessionToken();

        // Create session
        const session = {
            user_id: user.id,
            tenant_id: req.tenantId,
            token: sessionToken,
            refresh_token: refreshToken,
            ip_address: req.ip,
            user_agent: req.headers['user-agent'],
            is_active: true,
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + (remember_me ? 30 : 7) * 24 * 60 * 60 * 1000).toISOString(),
            last_activity: new Date().toISOString()
        };

        db.insert('user_sessions', session);

        // Update user login info
        db.query('users')
            .where('id', user.id)
            .update({
                last_login_at: new Date().toISOString(),
                last_login_ip: req.ip,
                failed_login_attempts: 0,
                is_locked: false,
                locked_until: null
            });

        // Log successful login
        db.insert('audit_log', {
            tenant_id: req.tenantId,
            user_id: user.id,
            action: 'login',
            resource: 'auth',
            ip_address: req.ip,
            user_agent: req.headers['user-agent'],
            created_at: new Date().toISOString()
        });

        res.json({
            access_token: accessToken,
            refresh_token: refreshToken,
            token_type: 'Bearer',
            expires_in: 900, // 15 minutes
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: role,
                permissions: permissions
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout endpoint
router.post('/logout', authenticate, async (req, res) => {
    try {
        // Invalidate current session
        db.query('user_sessions')
            .where('user_id', req.user.id)
            .where('is_active', true)
            .update({ is_active: false });

        // Log logout
        db.insert('audit_log', {
            tenant_id: req.user.tenant_id,
            user_id: req.user.id,
            action: 'logout',
            resource: 'auth',
            ip_address: req.ip,
            user_agent: req.headers['user-agent'],
            created_at: new Date().toISOString()
        });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Refresh token endpoint
router.post('/refresh', validateTenant, async (req, res) => {
    try {
        const { refresh_token } = req.body;

        if (!refresh_token) {
            return res.status(400).json({
                error: 'Refresh token required',
                code: 'NO_REFRESH_TOKEN'
            });
        }

        // Verify refresh token
        const decoded = verifyRefreshToken(refresh_token);

        // Find active session
        const session = db.query('user_sessions')
            .where('refresh_token', refresh_token)
            .where('user_id', decoded.id)
            .where('is_active', true)
            .first();

        if (!session) {
            return res.status(401).json({
                error: 'Invalid refresh token',
                code: 'INVALID_REFRESH_TOKEN'
            });
        }

        // Get user with permissions
        const user = db.query('users')
            .where('id', decoded.id)
            .where('tenant_id', decoded.tenant_id)
            .where('is_active', true)
            .first();

        if (!user) {
            return res.status(401).json({
                error: 'User not found or inactive',
                code: 'USER_INACTIVE'
            });
        }

        // Get permissions
        const rolePermissions = db.query('role_permissions')
            .where('role_id', user.role_id)
            .get();
        
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const permissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        // Generate new access token
        const userWithPermissions = { ...user, permissions };
        const newAccessToken = generateAccessToken(userWithPermissions);

        // Update session activity
        db.query('user_sessions')
            .where('id', session.id)
            .update({ last_activity: new Date().toISOString() });

        res.json({
            access_token: newAccessToken,
            token_type: 'Bearer',
            expires_in: 900
        });
    } catch (error) {
        if (error.message === 'REFRESH_TOKEN_EXPIRED') {
            return res.status(401).json({
                error: 'Refresh token has expired',
                code: 'REFRESH_TOKEN_EXPIRED'
            });
        }
        console.error('Token refresh error:', error);
        res.status(500).json({ error: 'Token refresh failed' });
    }
});

// Change password endpoint
router.post('/change-password', authenticate, async (req, res) => {
    try {
        const { error, value } = changePasswordSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { current_password, new_password } = value;

        // Get user
        const user = db.query('users')
            .where('id', req.user.id)
            .first();

        // Verify current password
        const validPassword = await verifyPassword(current_password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({
                error: 'Current password is incorrect',
                code: 'INVALID_CURRENT_PASSWORD'
            });
        }

        // Validate new password
        const passwordValidation = validatePassword(new_password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                error: 'Password does not meet requirements',
                code: 'INVALID_PASSWORD',
                requirements: passwordValidation.errors
            });
        }

        // Hash new password
        const newPasswordHash = await hashPassword(new_password);

        // Update password
        db.query('users')
            .where('id', req.user.id)
            .update({
                password_hash: newPasswordHash,
                password_changed_at: new Date().toISOString(),
                must_change_password: false
            });

        // Invalidate all sessions except current
        db.query('user_sessions')
            .where('user_id', req.user.id)
            .where('is_active', true)
            .whereNot('token', req.headers.authorization?.substring(7))
            .update({ is_active: false });

        // Log password change
        db.insert('audit_log', {
            tenant_id: req.user.tenant_id,
            user_id: req.user.id,
            action: 'change_password',
            resource: 'auth',
            ip_address: req.ip,
            user_agent: req.headers['user-agent'],
            created_at: new Date().toISOString()
        });

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Password change failed' });
    }
});

// Request password reset
router.post('/reset-password', validateTenant, rateLimitLogin, async (req, res) => {
    try {
        const { error, value } = resetPasswordSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { email } = value;

        // Find user
        const user = db.query('users')
            .where('email', email)
            .where('tenant_id', req.tenantId)
            .first();

        // Always return success to prevent email enumeration
        if (!user) {
            return res.json({
                message: 'If the email exists, a password reset link has been sent'
            });
        }

        // Generate reset token
        const resetToken = generateSessionToken();
        const resetEntry = {
            user_id: user.id,
            token: resetToken,
            expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour
            created_at: new Date().toISOString(),
            ip_address: req.ip
        };

        db.insert('password_resets', resetEntry);

        // In production, send email with reset link
        // For now, return token in development
        if (process.env.NODE_ENV === 'development') {
            return res.json({
                message: 'Password reset token generated',
                reset_token: resetToken // Remove in production
            });
        }

        res.json({
            message: 'If the email exists, a password reset link has been sent'
        });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Password reset request failed' });
    }
});

// Verify session endpoint
router.get('/verify', authenticate, (req, res) => {
    res.json({
        valid: true,
        user: {
            id: req.user.id,
            username: req.user.username,
            email: req.user.email,
            tenant_id: req.user.tenant_id,
            role_id: req.user.role_id,
            permissions: req.user.permissions
        }
    });
});

module.exports = router;