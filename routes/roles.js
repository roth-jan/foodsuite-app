// Role Management Routes for FoodSuite
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const {
    authenticate,
    authorize,
    validateTenant,
    auditLog
} = require('../middleware/auth-middleware');
const db = require('../database/db-memory');

// Validation schemas
const createRoleSchema = Joi.object({
    name: Joi.string().min(3).max(50).required(),
    description: Joi.string().max(200).required(),
    level: Joi.number().min(1).max(10).required(),
    permissions: Joi.array().items(Joi.number()).required()
});

const updateRoleSchema = Joi.object({
    name: Joi.string().min(3).max(50).optional(),
    description: Joi.string().max(200).optional(),
    level: Joi.number().min(1).max(10).optional(),
    permissions: Joi.array().items(Joi.number()).optional()
});

// Get all roles
router.get('/', 
    authenticate, 
    validateTenant,
    async (req, res) => {
    try {
        const roles = db.query('roles')
            .where('tenant_id', req.tenantId)
            .orWhere('is_system', true)
            .orderBy('level', 'asc')
            .get();

        // Get permissions for each role
        const rolesWithPermissions = await Promise.all(roles.map(async role => {
            const rolePermissions = db.query('role_permissions')
                .where('role_id', role.id)
                .get();
            
            const permissionIds = rolePermissions.map(rp => rp.permission_id);
            const permissions = db.query('permissions')
                .whereIn('id', permissionIds)
                .get();

            // Get user count for this role
            const userCount = db.query('users')
                .where('role_id', role.id)
                .where('tenant_id', req.tenantId)
                .count();

            return {
                ...role,
                permissions,
                user_count: userCount,
                can_delete: !role.is_system && userCount === 0
            };
        }));

        res.json(rolesWithPermissions);
    } catch (error) {
        console.error('Get roles error:', error);
        res.status(500).json({ error: 'Failed to fetch roles' });
    }
});

// Get single role
router.get('/:id', 
    authenticate, 
    validateTenant,
    async (req, res) => {
    try {
        const roleId = parseInt(req.params.id);

        const role = db.query('roles')
            .where('id', roleId)
            .where(function() {
                this.where('tenant_id', req.tenantId)
                    .orWhere('is_system', true);
            })
            .first();

        if (!role) {
            return res.status(404).json({ error: 'Role not found' });
        }

        // Get permissions
        const rolePermissions = db.query('role_permissions')
            .where('role_id', roleId)
            .get();
        
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const permissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        // Get users with this role
        const users = db.query('users')
            .where('role_id', roleId)
            .where('tenant_id', req.tenantId)
            .select(['id', 'username', 'email', 'first_name', 'last_name'])
            .get();

        res.json({
            ...role,
            permissions,
            users,
            can_edit: !role.is_system,
            can_delete: !role.is_system && users.length === 0
        });
    } catch (error) {
        console.error('Get role error:', error);
        res.status(500).json({ error: 'Failed to fetch role' });
    }
});

// Get all available permissions
router.get('/permissions/all', 
    authenticate, 
    async (req, res) => {
    try {
        const permissions = db.query('permissions')
            .orderBy('category', 'asc')
            .orderBy('resource', 'asc')
            .orderBy('action', 'asc')
            .get();

        // Group by category
        const groupedPermissions = permissions.reduce((acc, permission) => {
            const category = permission.category || 'Andere';
            if (!acc[category]) {
                acc[category] = [];
            }
            acc[category].push(permission);
            return acc;
        }, {});

        res.json({
            permissions,
            grouped: groupedPermissions
        });
    } catch (error) {
        console.error('Get permissions error:', error);
        res.status(500).json({ error: 'Failed to fetch permissions' });
    }
});

// Create new role
router.post('/', 
    authenticate, 
    authorize('settings', 'manage'),
    validateTenant,
    auditLog('roles', 'create'),
    async (req, res) => {
    try {
        const { error, value } = createRoleSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { permissions, ...roleData } = value;

        // Check if role name already exists
        const existingRole = db.query('roles')
            .where('name', roleData.name)
            .where('tenant_id', req.tenantId)
            .first();

        if (existingRole) {
            return res.status(409).json({ 
                error: 'Role name already exists',
                code: 'ROLE_EXISTS'
            });
        }

        // Create role
        const newRole = {
            ...roleData,
            tenant_id: req.tenantId,
            is_system: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };

        const roleId = db.insert('roles', newRole);

        // Assign permissions
        const rolePermissions = permissions.map(permissionId => ({
            role_id: roleId,
            permission_id: permissionId,
            granted_at: new Date().toISOString(),
            granted_by: req.user.id
        }));

        rolePermissions.forEach(rp => db.insert('role_permissions', rp));

        // Get created role with permissions
        const createdRole = db.query('roles').where('id', roleId).first();
        const assignedPermissions = db.query('permissions')
            .whereIn('id', permissions)
            .get();

        res.status(201).json({
            ...createdRole,
            permissions: assignedPermissions
        });
    } catch (error) {
        console.error('Create role error:', error);
        res.status(500).json({ error: 'Failed to create role' });
    }
});

// Update role
router.put('/:id', 
    authenticate, 
    authorize('settings', 'manage'),
    validateTenant,
    auditLog('roles', 'update'),
    async (req, res) => {
    try {
        const roleId = parseInt(req.params.id);
        const { error, value } = updateRoleSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        // Check if role exists
        const existingRole = db.query('roles')
            .where('id', roleId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!existingRole) {
            return res.status(404).json({ error: 'Role not found' });
        }

        if (existingRole.is_system) {
            return res.status(403).json({ 
                error: 'Cannot modify system roles',
                code: 'SYSTEM_ROLE'
            });
        }

        // Check name uniqueness if changing
        if (value.name && value.name !== existingRole.name) {
            const nameExists = db.query('roles')
                .where('name', value.name)
                .where('tenant_id', req.tenantId)
                .whereNot('id', roleId)
                .first();

            if (nameExists) {
                return res.status(409).json({ 
                    error: 'Role name already exists',
                    code: 'ROLE_EXISTS'
                });
            }
        }

        // Update role
        const { permissions, ...roleUpdates } = value;
        
        if (Object.keys(roleUpdates).length > 0) {
            roleUpdates.updated_at = new Date().toISOString();
            db.query('roles')
                .where('id', roleId)
                .update(roleUpdates);
        }

        // Update permissions if provided
        if (permissions) {
            // Remove old permissions
            db.query('role_permissions')
                .where('role_id', roleId)
                .delete();

            // Add new permissions
            const rolePermissions = permissions.map(permissionId => ({
                role_id: roleId,
                permission_id: permissionId,
                granted_at: new Date().toISOString(),
                granted_by: req.user.id
            }));

            rolePermissions.forEach(rp => db.insert('role_permissions', rp));
        }

        // Get updated role with permissions
        const updatedRole = db.query('roles').where('id', roleId).first();
        const rolePermissions = db.query('role_permissions')
            .where('role_id', roleId)
            .get();
        
        const permissionIds = rolePermissions.map(rp => rp.permission_id);
        const assignedPermissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        res.json({
            ...updatedRole,
            permissions: assignedPermissions
        });
    } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({ error: 'Failed to update role' });
    }
});

// Delete role
router.delete('/:id', 
    authenticate, 
    authorize('settings', 'manage'),
    validateTenant,
    auditLog('roles', 'delete'),
    async (req, res) => {
    try {
        const roleId = parseInt(req.params.id);

        const role = db.query('roles')
            .where('id', roleId)
            .where('tenant_id', req.tenantId)
            .first();

        if (!role) {
            return res.status(404).json({ error: 'Role not found' });
        }

        if (role.is_system) {
            return res.status(403).json({ 
                error: 'Cannot delete system roles',
                code: 'SYSTEM_ROLE'
            });
        }

        // Check if role is in use
        const userCount = db.query('users')
            .where('role_id', roleId)
            .where('tenant_id', req.tenantId)
            .count();

        if (userCount > 0) {
            return res.status(409).json({ 
                error: 'Cannot delete role that is assigned to users',
                code: 'ROLE_IN_USE',
                user_count: userCount
            });
        }

        // Delete role permissions
        db.query('role_permissions')
            .where('role_id', roleId)
            .delete();

        // Delete role
        db.query('roles')
            .where('id', roleId)
            .delete();

        res.json({ message: 'Role deleted successfully' });
    } catch (error) {
        console.error('Delete role error:', error);
        res.status(500).json({ error: 'Failed to delete role' });
    }
});

// Clone existing role
router.post('/:id/clone', 
    authenticate, 
    authorize('settings', 'manage'),
    validateTenant,
    auditLog('roles', 'clone'),
    async (req, res) => {
    try {
        const sourceRoleId = parseInt(req.params.id);
        const { name, description } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'New role name is required' });
        }

        // Get source role
        const sourceRole = db.query('roles')
            .where('id', sourceRoleId)
            .where(function() {
                this.where('tenant_id', req.tenantId)
                    .orWhere('is_system', true);
            })
            .first();

        if (!sourceRole) {
            return res.status(404).json({ error: 'Source role not found' });
        }

        // Check if new name already exists
        const existingRole = db.query('roles')
            .where('name', name)
            .where('tenant_id', req.tenantId)
            .first();

        if (existingRole) {
            return res.status(409).json({ 
                error: 'Role name already exists',
                code: 'ROLE_EXISTS'
            });
        }

        // Get source role permissions
        const sourcePermissions = db.query('role_permissions')
            .where('role_id', sourceRoleId)
            .get();

        // Create new role
        const newRole = {
            name,
            description: description || `Clone of ${sourceRole.name}`,
            level: sourceRole.level,
            tenant_id: req.tenantId,
            is_system: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };

        const newRoleId = db.insert('roles', newRole);

        // Copy permissions
        const newPermissions = sourcePermissions.map(sp => ({
            role_id: newRoleId,
            permission_id: sp.permission_id,
            granted_at: new Date().toISOString(),
            granted_by: req.user.id
        }));

        newPermissions.forEach(np => db.insert('role_permissions', np));

        // Get created role with permissions
        const createdRole = db.query('roles').where('id', newRoleId).first();
        const permissionIds = sourcePermissions.map(sp => sp.permission_id);
        const permissions = db.query('permissions')
            .whereIn('id', permissionIds)
            .get();

        res.status(201).json({
            ...createdRole,
            permissions,
            cloned_from: sourceRole.name
        });
    } catch (error) {
        console.error('Clone role error:', error);
        res.status(500).json({ error: 'Failed to clone role' });
    }
});

module.exports = router;