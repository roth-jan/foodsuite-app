// Authentication Manager for FoodSuite
class AuthManager {
    constructor() {
        this.API_BASE_URL = window.location.hostname === 'localhost' 
            ? 'http://localhost:3000/api' 
            : `${window.location.protocol}//${window.location.host}/api`;
        this.TENANT_ID = 'demo';
        this.refreshTokenInterval = null;
    }

    // Get stored tokens
    getAccessToken() {
        return localStorage.getItem('access_token');
    }

    getRefreshToken() {
        return localStorage.getItem('refresh_token');
    }

    getUser() {
        const userStr = localStorage.getItem('user');
        return userStr ? JSON.parse(userStr) : null;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.getAccessToken();
    }

    // Check if user has specific permission
    hasPermission(resource, action) {
        const user = this.getUser();
        if (!user || !user.permissions) return false;
        
        return user.permissions.some(p => 
            p.resource === resource && p.action === action
        );
    }

    // Check if user has specific role level
    hasRoleLevel(minLevel) {
        const user = this.getUser();
        if (!user || !user.role) return false;
        
        return user.role.level <= minLevel;
    }

    // Make authenticated API request
    async apiRequest(endpoint, options = {}) {
        const token = this.getAccessToken();
        
        if (!token) {
            throw new Error('Not authenticated');
        }

        const defaultHeaders = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            'x-tenant-id': this.TENANT_ID
        };

        const response = await fetch(`${this.API_BASE_URL}${endpoint}`, {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers
            }
        });

        // Handle token expiration
        if (response.status === 401) {
            const data = await response.json();
            
            if (data.code === 'TOKEN_EXPIRED') {
                // Try to refresh token
                const refreshed = await this.refreshAccessToken();
                
                if (refreshed) {
                    // Retry request with new token
                    return this.apiRequest(endpoint, options);
                } else {
                    // Refresh failed, redirect to login
                    this.logout();
                    return;
                }
            } else {
                // Other auth error, redirect to login
                this.logout();
                return;
            }
        }

        return response;
    }

    // Refresh access token
    async refreshAccessToken() {
        const refreshToken = this.getRefreshToken();
        
        if (!refreshToken) {
            return false;
        }

        try {
            const response = await fetch(`${this.API_BASE_URL}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-tenant-id': this.TENANT_ID
                },
                body: JSON.stringify({
                    refresh_token: refreshToken
                })
            });

            if (response.ok) {
                const data = await response.json();
                localStorage.setItem('access_token', data.access_token);
                return true;
            } else {
                return false;
            }
        } catch (error) {
            console.error('Token refresh error:', error);
            return false;
        }
    }

    // Start automatic token refresh
    startTokenRefresh() {
        // Refresh token every 10 minutes (before 15 min expiry)
        this.refreshTokenInterval = setInterval(() => {
            this.refreshAccessToken();
        }, 10 * 60 * 1000);
    }

    // Stop automatic token refresh
    stopTokenRefresh() {
        if (this.refreshTokenInterval) {
            clearInterval(this.refreshTokenInterval);
            this.refreshTokenInterval = null;
        }
    }

    // Logout
    async logout() {
        const token = this.getAccessToken();
        
        if (token) {
            try {
                await fetch(`${this.API_BASE_URL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'x-tenant-id': this.TENANT_ID
                    }
                });
            } catch (error) {
                console.error('Logout error:', error);
            }
        }

        // Clear local storage
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        
        // Stop token refresh
        this.stopTokenRefresh();
        
        // Redirect to login
        window.location.href = 'foodsuite-login.html';
    }

    // Initialize auth check
    async initialize() {
        if (!this.isAuthenticated()) {
            window.location.href = 'foodsuite-login.html';
            return false;
        }

        // Verify token is valid
        try {
            const response = await this.apiRequest('/auth/verify');
            
            if (!response.ok) {
                this.logout();
                return false;
            }

            // Start token refresh
            this.startTokenRefresh();
            
            // Update UI with user info
            this.updateUserInterface();
            
            return true;
        } catch (error) {
            console.error('Auth initialization error:', error);
            this.logout();
            return false;
        }
    }

    // Update UI with user information
    updateUserInterface() {
        const user = this.getUser();
        if (!user) return;

        // Update user name in UI
        const userNameElements = document.querySelectorAll('.user-name');
        userNameElements.forEach(el => {
            el.textContent = `${user.first_name} ${user.last_name}`;
        });

        // Update user role
        const userRoleElements = document.querySelectorAll('.user-role');
        userRoleElements.forEach(el => {
            el.textContent = user.role ? user.role.name : '';
        });

        // Hide/show elements based on permissions
        this.updatePermissionBasedUI();
    }

    // Update UI based on permissions
    updatePermissionBasedUI() {
        // Hide elements that require specific permissions
        const permissionElements = document.querySelectorAll('[data-permission]');
        
        permissionElements.forEach(el => {
            const permission = el.getAttribute('data-permission');
            const [resource, action] = permission.split(':');
            
            if (!this.hasPermission(resource, action)) {
                el.style.display = 'none';
            }
        });

        // Hide elements that require specific role levels
        const roleElements = document.querySelectorAll('[data-role-level]');
        
        roleElements.forEach(el => {
            const minLevel = parseInt(el.getAttribute('data-role-level'));
            
            if (!this.hasRoleLevel(minLevel)) {
                el.style.display = 'none';
            }
        });
    }

    // Show permission denied message
    showPermissionDenied() {
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-danger border-0 position-fixed bottom-0 end-0 m-3';
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="bi bi-shield-x me-2"></i>
                    Sie haben keine Berechtigung für diese Aktion.
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        document.body.appendChild(toast);
        
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }
}

// Create global instance
const authManager = new AuthManager();

// Export for use in other scripts
window.authManager = authManager;