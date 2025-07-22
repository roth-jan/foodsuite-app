// User Management Routes for FoodSuite
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const {
    hashPassword,
    generateSecurePassword,
    validatePassword
} = require('../utils/auth');
const {
    authenticate,
    authorize,
    validateTenant,
    auditLog
} = require('../middleware/auth-middleware');
const db = require('../database/db-memory');

// Validation schemas
const createUserSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).optional(),
    first_name: Joi.string().required(),
    last_name: Joi.string().required(),
    role_id: Joi.number().required(),
    is_active: Joi.boolean().default(true),
    must_change_password: Joi.boolean().default(true)
});

const updateUserSchema = Joi.object({
    email: Joi.string().email().optional(),
    first_name: Joi.string().optional(),
    last_name: Joi.string().optional(),
    role_id: Joi.number().optional(),
    is_active: Joi.boolean().optional(),
    preferences: Joi.object().optional()
});

const bulkOperationSchema = Joi.object({
    user_ids: Joi.array().items(Joi.number()).required(),
    operation: Joi.string().valid('activate', 'deactivate', 'delete', 'assign_role').required(),
    role_id: Joi.number().when('operation', {
        is: 'assign_role',
        then: Joi.required()
    })
});

// Get all users with pagination and filtering
router.get('/', 
    authenticate, 
    authorize('users', 'read'),
    validateTenant,
    async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;
        const search = req.query.search;
        const role_id = req.query.role_id;
        const is_active = req.query.is_active;

        let query = db.query('users')
            .where('tenant_id', req.tenantId);

        // Apply filters
        if (search) {
            query = query.where(function() {
                this.where('username', 'like', `%${search}%`)
                    .orWhere('email', 'like', `%${search}%`)
                    .orWhere('first_name', 'like', `%${search}%`)
                    .orWhere('last_name', 'like', `%${search}%`);
            });
        }

        if (role_id) {
            query = query.where('role_id', role_id);
        }

        if (is_active !== undefined) {
            query = query.where('is_active', is_active === 'true');
        }

        // Get total count
        const total = query.count();

        // Get paginated results
        const users = query
            .select(['id', 'username', 'email', 'first_name', 'last_name', 
                    'role_id', 'is_active', 'is_locked', 'last_login_at', 
                    'created_at', 'updated_at'])
            .limit(limit)
            .offset(offset)
            .orderBy('created_at', 'desc')
            .get();

        // Get roles for users
        const roleIds = [...new Set(users.map(u => u.role_id))];
        const roles = db.query('roles')
            .whereIn('id', roleIds)
            .get();

        const rolesMap = Object.fromEntries(roles.map(r => [r.id, r]));

        // Attach role info to users
        const usersWithRoles = users.map(user => ({
            ...user,
            role: rolesMap[user.role_id]
        }));

        res.json({
            users: usersWithRoles,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get single user
router.get('/:id', 
    authenticate, 
    authorize('users', 'read'),
    validateTenant,
    async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        // Users can view their own profile
        if (userId !== req.user.id && !req.user.permissions.some(p => p.resource === 'users' && p.action === 'read')) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        const user = db.query('users')
            .where('id', userId)
            .where('tenant_id', req.tenantId)
            .select(['id', 'username', 'email', 'first_name', 'last_name', 
                    'role_id', 'is_active', 'is_locked', 'last_login_at', 
                    'created_at', 'updated_at', 'preferences'])
            .first();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get role and permissions
        const role = db.query('roles').where('id', user.role_id).first();
        const rolePermissions = db.query('role_permissions')
            .where('role_id', user.role_id)
            .get();
        
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const permissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        // Get activity summary
        const recentActivity = db.query('audit_log')
            .where('user_id', userId)
            .orderBy('created_at', 'desc')
            .limit(10)
            .get();

        res.json({
            ...user,
            role,
            permissions,
            recent_activity: recentActivity
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// Create new user
router.post('/', 
    authenticate, 
    authorize('users', 'create'),
    validateTenant,
    auditLog('users', 'create'),
    async (req, res) => {
    try {
        const { error, value } = createUserSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        // Check if username already exists
        const existingUser = db.query('users')
            .where('username', value.username)
            .where('tenant_id', req.tenantId)
            .first();

        if (existingUser) {
            return res.status(409).json({ 
                error: 'Username already exists',
                code: 'USERNAME_EXISTS'
            });
        }

        // Check if email already exists
        const existingEmail = db.query('users')
            .where('email', value.email)
            .where('tenant_id', req.tenantId)
            .first();

        if (existingEmail) {
            return res.status(409).json({ 
                error: 'Email already exists',
                code: 'EMAIL_EXISTS'
            });
        }

        // Generate password if not provided
        let password = value.password;
        if (!password) {
            password = generateSecurePassword();
            value.must_change_password = true;
        } else {
            // Validate provided password
            const passwordValidation = validatePassword(password);
            if (!passwordValidation.valid) {
                return res.status(400).json({
                    error: 'Password does not meet requirements',
                    code: 'INVALID_PASSWORD',
                    requirements: passwordValidation.errors
                });
            }
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Create user
        const newUser = {
            ...value,
            password_hash: passwordHash,
            tenant_id: req.tenantId,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            created_by: req.user.id,
            failed_login_attempts: 0,
            is_locked: false,
            two_factor_enabled: false
        };

        delete newUser.password; // Remove plain password

        const userId = db.insert('users', newUser);
        const createdUser = db.query('users').where('id', userId).first();

        // Get role info
        const role = db.query('roles').where('id', createdUser.role_id).first();

        res.status(201).json({
            user: {
                ...createdUser,
                role
            },
            temporary_password: value.password ? undefined : password // Only return if generated
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Update user
router.put('/:id', 
    authenticate, 
    authorize('users', 'update'),
    validateTenant,
    auditLog('users', 'update'),
    async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { error, value } = updateUserSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        // Check if user exists
        const existingUser = db.query('users')
            .where('id', userId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check email uniqueness if changing
        if (value.email && value.email !== existingUser.email) {
            const emailExists = db.query('users')
                .where('email', value.email)
                .where('tenant_id', req.tenantId)
                .whereNot('id', userId)
                .first();

            if (emailExists) {
                return res.status(409).json({ 
                    error: 'Email already exists',
                    code: 'EMAIL_EXISTS'
                });
            }
        }

        // Prevent users from changing their own role
        if (value.role_id && userId === req.user.id) {
            return res.status(403).json({ 
                error: 'Cannot change your own role',
                code: 'SELF_ROLE_CHANGE'
            });
        }

        // Update user
        const updates = {
            ...value,
            updated_at: new Date().toISOString()
        };

        db.query('users')
            .where('id', userId)
            .update(updates);

        const updatedUser = db.query('users')
            .where('id', userId)
            .select(['id', 'username', 'email', 'first_name', 'last_name', 
                    'role_id', 'is_active', 'is_locked', 'preferences'])
            .first();

        const role = db.query('roles').where('id', updatedUser.role_id).first();

        res.json({
            ...updatedUser,
            role
        });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Delete user
router.delete('/:id', 
    authenticate, 
    authorize('users', 'delete'),
    validateTenant,
    auditLog('users', 'delete'),
    async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        // Prevent self-deletion
        if (userId === req.user.id) {
            return res.status(403).json({ 
                error: 'Cannot delete your own account',
                code: 'SELF_DELETE'
            });
        }

        const user = db.query('users')
            .where('id', userId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Soft delete by deactivating
        db.query('users')
            .where('id', userId)
            .update({
                is_active: false,
                updated_at: new Date().toISOString()
            });

        // Invalidate all user sessions
        db.query('user_sessions')
            .where('user_id', userId)
            .update({ is_active: false });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Reset user password
router.post('/:id/reset-password', 
    authenticate, 
    authorize('users', 'update'),
    validateTenant,
    auditLog('users', 'reset_password'),
    async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        const user = db.query('users')
            .where('id', userId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate new password
        const newPassword = generateSecurePassword();
        const passwordHash = await hashPassword(newPassword);

        // Update user
        db.query('users')
            .where('id', userId)
            .update({
                password_hash: passwordHash,
                must_change_password: true,
                updated_at: new Date().toISOString()
            });

        // Invalidate all user sessions
        db.query('user_sessions')
            .where('user_id', userId)
            .update({ is_active: false });

        res.json({
            message: 'Password reset successfully',
            temporary_password: newPassword
        });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Unlock user account
router.post('/:id/unlock', 
    authenticate, 
    authorize('users', 'update'),
    validateTenant,
    auditLog('users', 'unlock'),
    async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        const user = db.query('users')
            .where('id', userId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Unlock account
        db.query('users')
            .where('id', userId)
            .update({
                is_locked: false,
                locked_until: null,
                failed_login_attempts: 0,
                updated_at: new Date().toISOString()
            });

        res.json({ message: 'Account unlocked successfully' });
    } catch (error) {
        console.error('Unlock account error:', error);
        res.status(500).json({ error: 'Failed to unlock account' });
    }
});

// Bulk operations
router.post('/bulk', 
    authenticate, 
    authorize('users', 'update'),
    validateTenant,
    auditLog('users', 'bulk_operation'),
    async (req, res) => {
    try {
        const { error, value } = bulkOperationSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { user_ids, operation, role_id } = value;

        // Prevent self-operations
        if (user_ids.includes(req.user.id)) {
            return res.status(403).json({ 
                error: 'Cannot perform bulk operations on your own account',
                code: 'SELF_OPERATION'
            });
        }

        // Verify all users exist and belong to tenant
        const users = db.query('users')
            .whereIn('id', user_ids)
            .where('tenant_id', req.tenantId)
            .get();

        if (users.length !== user_ids.length) {
            return res.status(400).json({ 
                error: 'Some users not found or belong to different tenant' 
            });
        }

        let updates = { updated_at: new Date().toISOString() };
        let message = '';

        switch (operation) {
            case 'activate':
                updates.is_active = true;
                message = 'Users activated successfully';
                break;
            case 'deactivate':
                updates.is_active = false;
                message = 'Users deactivated successfully';
                break;
            case 'delete':
                updates.is_active = false;
                message = 'Users deleted successfully';
                break;
            case 'assign_role':
                updates.role_id = role_id;
                message = 'Role assigned successfully';
                break;
        }

        // Apply updates
        db.query('users')
            .whereIn('id', user_ids)
            .update(updates);

        // Invalidate sessions for deactivated users
        if (['deactivate', 'delete'].includes(operation)) {
            db.query('user_sessions')
                .whereIn('user_id', user_ids)
                .update({ is_active: false });
        }

        res.json({
            message,
            affected_users: user_ids.length
        });
    } catch (error) {
        console.error('Bulk operation error:', error);
        res.status(500).json({ error: 'Bulk operation failed' });
    }
});

module.exports = router;