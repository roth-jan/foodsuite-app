// Authentication and Authorization Schema for FoodSuite

const authSchema = {
    // User table with enhanced security fields
    users: {
        id: 'number',
        tenant_id: 'string',
        username: 'string', // unique per tenant
        email: 'string',
        password_hash: 'string',
        first_name: 'string',
        last_name: 'string',
        role_id: 'number',
        is_active: 'boolean',
        is_locked: 'boolean',
        failed_login_attempts: 'number',
        locked_until: 'datetime',
        must_change_password: 'boolean',
        password_changed_at: 'datetime',
        created_at: 'datetime',
        updated_at: 'datetime',
        created_by: 'number',
        last_login_at: 'datetime',
        last_login_ip: 'string',
        two_factor_enabled: 'boolean',
        two_factor_secret: 'string',
        preferences: 'json' // UI preferences, language, etc.
    },

    // Roles with hierarchical structure
    roles: {
        id: 'number',
        tenant_id: 'string',
        name: 'string',
        description: 'string',
        level: 'number', // 1=Admin, 2=Manager, 3=Chef, 4=Staff, 5=Viewer
        is_system: 'boolean', // System roles cannot be deleted
        created_at: 'datetime',
        updated_at: 'datetime'
    },

    // Granular permissions
    permissions: {
        id: 'number',
        resource: 'string', // e.g., 'products', 'orders', 'users'
        action: 'string', // e.g., 'create', 'read', 'update', 'delete', 'approve'
        description: 'string',
        category: 'string' // Group permissions by category
    },

    // Role-Permission mapping
    role_permissions: {
        id: 'number',
        role_id: 'number',
        permission_id: 'number',
        granted_at: 'datetime',
        granted_by: 'number'
    },

    // User sessions for JWT management
    user_sessions: {
        id: 'number',
        user_id: 'number',
        tenant_id: 'string',
        token: 'string',
        refresh_token: 'string',
        ip_address: 'string',
        user_agent: 'string',
        is_active: 'boolean',
        created_at: 'datetime',
        expires_at: 'datetime',
        last_activity: 'datetime'
    },

    // Audit log for security tracking
    audit_log: {
        id: 'number',
        tenant_id: 'string',
        user_id: 'number',
        action: 'string',
        resource: 'string',
        resource_id: 'number',
        old_values: 'json',
        new_values: 'json',
        ip_address: 'string',
        user_agent: 'string',
        created_at: 'datetime'
    },

    // Password reset tokens
    password_resets: {
        id: 'number',
        user_id: 'number',
        token: 'string',
        expires_at: 'datetime',
        used_at: 'datetime',
        created_at: 'datetime',
        ip_address: 'string'
    }
};

// Default system roles
const systemRoles = [
    {
        id: 1,
        name: 'Administrator',
        description: 'Vollständiger Systemzugriff',
        level: 1,
        is_system: true
    },
    {
        id: 2,
        name: 'Küchenleiter',
        description: 'Verwaltung von Küche und Speiseplänen',
        level: 2,
        is_system: true
    },
    {
        id: 3,
        name: 'Koch',
        description: 'Zugriff auf Rezepte und Bestellungen',
        level: 3,
        is_system: true
    },
    {
        id: 4,
        name: 'Mitarbeiter',
        description: 'Basiszugriff für Küchenpersonal',
        level: 4,
        is_system: true
    },
    {
        id: 5,
        name: 'Betrachter',
        description: 'Nur-Lese-Zugriff',
        level: 5,
        is_system: true
    }
];

// Default permissions structure
const systemPermissions = [
    // User Management
    { id: 1, resource: 'users', action: 'create', description: 'Benutzer erstellen', category: 'Benutzerverwaltung' },
    { id: 2, resource: 'users', action: 'read', description: 'Benutzer anzeigen', category: 'Benutzerverwaltung' },
    { id: 3, resource: 'users', action: 'update', description: 'Benutzer bearbeiten', category: 'Benutzerverwaltung' },
    { id: 4, resource: 'users', action: 'delete', description: 'Benutzer löschen', category: 'Benutzerverwaltung' },
    { id: 5, resource: 'users', action: 'manage_roles', description: 'Rollen zuweisen', category: 'Benutzerverwaltung' },
    
    // Product Management
    { id: 6, resource: 'products', action: 'create', description: 'Produkte erstellen', category: 'Produktverwaltung' },
    { id: 7, resource: 'products', action: 'read', description: 'Produkte anzeigen', category: 'Produktverwaltung' },
    { id: 8, resource: 'products', action: 'update', description: 'Produkte bearbeiten', category: 'Produktverwaltung' },
    { id: 9, resource: 'products', action: 'delete', description: 'Produkte löschen', category: 'Produktverwaltung' },
    { id: 10, resource: 'products', action: 'manage_stock', description: 'Lagerbestand verwalten', category: 'Produktverwaltung' },
    
    // Order Management
    { id: 11, resource: 'orders', action: 'create', description: 'Bestellungen erstellen', category: 'Bestellwesen' },
    { id: 12, resource: 'orders', action: 'read', description: 'Bestellungen anzeigen', category: 'Bestellwesen' },
    { id: 13, resource: 'orders', action: 'update', description: 'Bestellungen bearbeiten', category: 'Bestellwesen' },
    { id: 14, resource: 'orders', action: 'delete', description: 'Bestellungen stornieren', category: 'Bestellwesen' },
    { id: 15, resource: 'orders', action: 'approve', description: 'Bestellungen freigeben', category: 'Bestellwesen' },
    
    // Recipe Management
    { id: 16, resource: 'recipes', action: 'create', description: 'Rezepte erstellen', category: 'Rezeptverwaltung' },
    { id: 17, resource: 'recipes', action: 'read', description: 'Rezepte anzeigen', category: 'Rezeptverwaltung' },
    { id: 18, resource: 'recipes', action: 'update', description: 'Rezepte bearbeiten', category: 'Rezeptverwaltung' },
    { id: 19, resource: 'recipes', action: 'delete', description: 'Rezepte löschen', category: 'Rezeptverwaltung' },
    
    // Meal Planning
    { id: 20, resource: 'mealplans', action: 'create', description: 'Speisepläne erstellen', category: 'Speiseplanung' },
    { id: 21, resource: 'mealplans', action: 'read', description: 'Speisepläne anzeigen', category: 'Speiseplanung' },
    { id: 22, resource: 'mealplans', action: 'update', description: 'Speisepläne bearbeiten', category: 'Speiseplanung' },
    { id: 23, resource: 'mealplans', action: 'delete', description: 'Speisepläne löschen', category: 'Speiseplanung' },
    { id: 24, resource: 'mealplans', action: 'approve', description: 'Speisepläne freigeben', category: 'Speiseplanung' },
    
    // Analytics
    { id: 25, resource: 'analytics', action: 'view_costs', description: 'Kostenanalysen anzeigen', category: 'Berichte' },
    { id: 26, resource: 'analytics', action: 'view_consumption', description: 'Verbrauchsstatistiken anzeigen', category: 'Berichte' },
    { id: 27, resource: 'analytics', action: 'export', description: 'Berichte exportieren', category: 'Berichte' },
    
    // System Settings
    { id: 28, resource: 'settings', action: 'manage', description: 'Systemeinstellungen verwalten', category: 'System' },
    { id: 29, resource: 'suppliers', action: 'manage', description: 'Lieferanten verwalten', category: 'System' },
    { id: 30, resource: 'automation', action: 'configure', description: 'Automatisierung konfigurieren', category: 'System' }
];

// Default role-permission mappings
const defaultRolePermissions = {
    // Administrator - all permissions
    1: systemPermissions.map(p => p.id),
    
    // Küchenleiter - most permissions except user management
    2: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30],
    
    // Koch - recipe and order management
    3: [7, 10, 11, 12, 13, 16, 17, 18, 20, 21, 22, 25, 26],
    
    // Mitarbeiter - basic read and create
    4: [7, 11, 12, 17, 21],
    
    // Betrachter - read only
    5: [2, 7, 12, 17, 21, 25, 26]
};

module.exports = {
    authSchema,
    systemRoles,
    systemPermissions,
    defaultRolePermissions
};