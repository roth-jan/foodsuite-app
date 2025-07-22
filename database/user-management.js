// User Management System for FoodSuite
// Defines roles, permissions, and user data

const userRoles = {
    admin: {
        name: 'Administrator',
        description: 'Vollzugriff auf alle Funktionen',
        permissions: [
            'user_management',
            'tenant_management', 
            'meal_planning_full',
            'inventory_full',
            'orders_full',
            'recipes_full',
            'suppliers_full',
            'analytics_full',
            'settings_full',
            'approve_meal_plans',
            'delete_data',
            'export_data'
        ],
        icon: 'shield-check',
        color: '#dc3545'
    },
    
    manager: {
        name: 'Küchenleiter',
        description: 'Speiseplanung und Personalverwaltung',
        permissions: [
            'meal_planning_full',
            'inventory_read',
            'inventory_update',
            'orders_read',
            'orders_create',
            'recipes_full',
            'suppliers_read',
            'analytics_read',
            'approve_meal_plans',
            'manage_staff',
            'view_costs'
        ],
        icon: 'person-badge',
        color: '#0d6efd'
    },
    
    chef: {
        name: 'Küchenchef',
        description: 'Rezepte und Speiseplanung',
        permissions: [
            'meal_planning_create',
            'meal_planning_update',
            'recipes_full',
            'inventory_read',
            'orders_read',
            'suppliers_read',
            'analytics_read',
            'submit_meal_plans'
        ],
        icon: 'person-workspace',
        color: '#198754'
    },
    
    sous_chef: {
        name: 'Sous Chef',
        description: 'Assistenz bei Rezepten und Planung',
        permissions: [
            'meal_planning_create',
            'recipes_read',
            'recipes_create',
            'inventory_read',
            'orders_read',
            'suppliers_read',
            'submit_meal_plans'
        ],
        icon: 'person-plus',
        color: '#fd7e14'
    },
    
    nutritionist: {
        name: 'Ernährungsberater',
        description: 'Nährwertanalyse und gesunde Speiseplanung',
        permissions: [
            'meal_planning_create',
            'recipes_read',
            'recipes_update_nutrition',
            'analytics_nutrition',
            'view_nutrition_reports',
            'suggest_improvements'
        ],
        icon: 'heart-pulse',
        color: '#20c997'
    },
    
    inventory_manager: {
        name: 'Lagerverwalter',
        description: 'Lagerverwaltung und Bestellungen',
        permissions: [
            'inventory_full',
            'orders_full',
            'suppliers_full',
            'meal_planning_read',
            'recipes_read',
            'analytics_inventory',
            'manage_stock'
        ],
        icon: 'boxes',
        color: '#6f42c1'
    },
    
    viewer: {
        name: 'Betrachter',
        description: 'Nur Lesezugriff',
        permissions: [
            'meal_planning_read',
            'recipes_read',
            'inventory_read',
            'orders_read',
            'suppliers_read',
            'analytics_read'
        ],
        icon: 'eye',
        color: '#6c757d'
    }
};

const users = [
    {
        id: 1,
        tenant_id: 1,
        username: 'admin',
        email: 'admin@kantine-hauptwerk.de',
        firstName: 'Max',
        lastName: 'Administrator',
        role: 'admin',
        isActive: true,
        lastLogin: new Date().toISOString(),
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'light',
            notifications: true,
            autoApprove: false
        }
    },
    {
        id: 2,
        tenant_id: 1,
        username: 'chef.mueller',
        email: 'mueller@kantine-hauptwerk.de',
        firstName: 'Anna',
        lastName: 'Müller',
        role: 'chef',
        isActive: true,
        lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'light',
            notifications: true,
            autoApprove: true
        }
    },
    {
        id: 3,
        tenant_id: 1,
        username: 'manager.schmidt',
        email: 'schmidt@kantine-hauptwerk.de',
        firstName: 'Thomas',
        lastName: 'Schmidt',
        role: 'manager',
        isActive: true,
        lastLogin: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'dark',
            notifications: true,
            autoApprove: false
        }
    },
    {
        id: 4,
        tenant_id: 1,
        username: 'nutritionist.weber',
        email: 'weber@kantine-hauptwerk.de',
        firstName: 'Lisa',
        lastName: 'Weber',
        role: 'nutritionist',
        isActive: true,
        lastLogin: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'light',
            notifications: true,
            autoApprove: true
        }
    },
    {
        id: 5,
        tenant_id: 1,
        username: 'inventory.fischer',
        email: 'fischer@kantine-hauptwerk.de',
        firstName: 'Michael',
        lastName: 'Fischer',
        role: 'inventory_manager',
        isActive: true,
        lastLogin: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'light',
            notifications: true,
            autoApprove: false
        }
    },
    {
        id: 6,
        tenant_id: 1,
        username: 'sous.wagner',
        email: 'wagner@kantine-hauptwerk.de',
        firstName: 'Sarah',
        lastName: 'Wagner',
        role: 'sous_chef',
        isActive: true,
        lastLogin: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
        createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
        avatar: null,
        preferences: {
            language: 'de',
            theme: 'light',
            notifications: false,
            autoApprove: true
        }
    }
];

// Meal plan approval workflow states
const approvalStates = {
    draft: {
        name: 'Entwurf',
        description: 'Speiseplan wird erstellt',
        color: '#6c757d',
        icon: 'pencil',
        canEdit: true,
        nextStates: ['submitted', 'cancelled']
    },
    submitted: {
        name: 'Eingereicht',
        description: 'Wartet auf Genehmigung',
        color: '#fd7e14',
        icon: 'clock',
        canEdit: false,
        nextStates: ['approved', 'rejected', 'revision_requested']
    },
    revision_requested: {
        name: 'Überarbeitung',
        description: 'Änderungen erforderlich',
        color: '#ffc107',
        icon: 'arrow-clockwise',
        canEdit: true,
        nextStates: ['submitted', 'cancelled']
    },
    approved: {
        name: 'Genehmigt',
        description: 'Speiseplan ist freigegeben',
        color: '#198754',
        icon: 'check-circle',
        canEdit: false,
        nextStates: ['published', 'revision_requested']
    },
    published: {
        name: 'Veröffentlicht',
        description: 'Speiseplan ist aktiv',
        color: '#0d6efd',
        icon: 'broadcast',
        canEdit: false,
        nextStates: ['archived']
    },
    rejected: {
        name: 'Abgelehnt',
        description: 'Speiseplan wurde abgelehnt',
        color: '#dc3545',
        icon: 'x-circle',
        canEdit: false,
        nextStates: ['draft']
    },
    cancelled: {
        name: 'Storniert',
        description: 'Speiseplan wurde storniert',
        color: '#6c757d',
        icon: 'slash-circle',
        canEdit: false,
        nextStates: ['draft']
    },
    archived: {
        name: 'Archiviert',
        description: 'Speiseplan ist abgeschlossen',
        color: '#495057',
        icon: 'archive',
        canEdit: false,
        nextStates: []
    }
};

// Permission helper functions
function hasPermission(user, permission) {
    const role = userRoles[user.role];
    return role && role.permissions.includes(permission);
}

function canApproveForRole(userRole, targetRole) {
    const hierarchy = {
        admin: 100,
        manager: 80,
        chef: 60,
        sous_chef: 40,
        nutritionist: 40,
        inventory_manager: 40,
        viewer: 10
    };
    
    return hierarchy[userRole] > hierarchy[targetRole];
}

function getPermissionsForRole(roleName) {
    return userRoles[roleName]?.permissions || [];
}

function getRoleHierarchy() {
    return {
        admin: ['manager', 'chef', 'sous_chef', 'nutritionist', 'inventory_manager', 'viewer'],
        manager: ['chef', 'sous_chef', 'nutritionist', 'inventory_manager', 'viewer'],
        chef: ['sous_chef'],
        sous_chef: [],
        nutritionist: [],
        inventory_manager: ['viewer'],
        viewer: []
    };
}

module.exports = {
    userRoles,
    users,
    approvalStates,
    hasPermission,
    canApproveForRole,
    getPermissionsForRole,
    getRoleHierarchy
};