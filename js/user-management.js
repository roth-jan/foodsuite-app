// User Management UI for FoodSuite
class UserManagement {
    constructor() {
        this.users = [];
        this.roles = [];
        this.permissions = [];
        this.currentEditUser = null;
    }

    async initialize() {
        // Load roles and permissions
        await this.loadRoles();
        await this.loadPermissions();
        
        // Load users
        await this.loadUsers();
        
        // Setup event listeners
        this.setupEventListeners();
    }

    setupEventListeners() {
        // New user button
        const newUserBtn = document.getElementById('newUserBtn');
        if (newUserBtn) {
            newUserBtn.addEventListener('click', () => this.showUserModal());
        }

        // Search functionality
        const searchInput = document.getElementById('userSearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.filterUsers(e.target.value));
        }

        // Role filter
        const roleFilter = document.getElementById('roleFilter');
        if (roleFilter) {
            roleFilter.addEventListener('change', (e) => this.filterByRole(e.target.value));
        }

        // User form submission
        const userForm = document.getElementById('userForm');
        if (userForm) {
            userForm.addEventListener('submit', (e) => this.handleUserSubmit(e));
        }
    }

    async loadUsers() {
        try {
            const response = await authManager.apiRequest('/users');
            if (response.ok) {
                const data = await response.json();
                this.users = data.users;
                this.renderUserTable();
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.showError('Fehler beim Laden der Benutzer');
        }
    }

    async loadRoles() {
        try {
            const response = await authManager.apiRequest('/roles');
            if (response.ok) {
                this.roles = await response.json();
                this.updateRoleSelects();
            }
        } catch (error) {
            console.error('Error loading roles:', error);
        }
    }

    async loadPermissions() {
        try {
            const response = await authManager.apiRequest('/roles/permissions/all');
            if (response.ok) {
                const data = await response.json();
                this.permissions = data.permissions;
            }
        } catch (error) {
            console.error('Error loading permissions:', error);
        }
    }

    renderUserTable() {
        const tbody = document.getElementById('userTableBody');
        if (!tbody) return;

        tbody.innerHTML = this.users.map(user => `
            <tr>
                <td>
                    <div class="d-flex align-items-center">
                        <div class="avatar-sm bg-primary text-white rounded-circle d-flex align-items-center justify-content-center me-3">
                            ${user.first_name.charAt(0)}${user.last_name.charAt(0)}
                        </div>
                        <div>
                            <div class="fw-bold">${user.first_name} ${user.last_name}</div>
                            <small class="text-muted">${user.username}</small>
                        </div>
                    </div>
                </td>
                <td>${user.email}</td>
                <td>
                    <span class="badge bg-${this.getRoleBadgeColor(user.role.level)}">
                        ${user.role.name}
                    </span>
                </td>
                <td>
                    ${user.is_active 
                        ? '<span class="badge bg-success">Aktiv</span>'
                        : '<span class="badge bg-danger">Inaktiv</span>'}
                    ${user.is_locked 
                        ? '<span class="badge bg-warning ms-1">Gesperrt</span>'
                        : ''}
                </td>
                <td>${user.last_login_at ? new Date(user.last_login_at).toLocaleString('de-DE') : 'Nie'}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button class="btn btn-outline-primary" onclick="userManagement.editUser(${user.id})" 
                                data-permission="users:update">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button class="btn btn-outline-warning" onclick="userManagement.resetPassword(${user.id})"
                                data-permission="users:update">
                            <i class="bi bi-key"></i>
                        </button>
                        ${user.is_locked ? `
                            <button class="btn btn-outline-success" onclick="userManagement.unlockUser(${user.id})"
                                    data-permission="users:update">
                                <i class="bi bi-unlock"></i>
                            </button>
                        ` : ''}
                        <button class="btn btn-outline-danger" onclick="userManagement.deleteUser(${user.id})"
                                data-permission="users:delete">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        // Update permission-based UI
        authManager.updatePermissionBasedUI();
    }

    getRoleBadgeColor(level) {
        switch (level) {
            case 1: return 'danger';    // Admin
            case 2: return 'warning';   // Manager
            case 3: return 'info';      // Chef
            case 4: return 'secondary'; // Staff
            case 5: return 'light';     // Viewer
            default: return 'secondary';
        }
    }

    updateRoleSelects() {
        const selects = document.querySelectorAll('.role-select');
        selects.forEach(select => {
            select.innerHTML = '<option value="">Rolle wählen...</option>' +
                this.roles.map(role => 
                    `<option value="${role.id}">${role.name} (Level ${role.level})</option>`
                ).join('');
        });
    }

    showUserModal(userId = null) {
        this.currentEditUser = userId;
        const modal = new bootstrap.Modal(document.getElementById('userModal'));
        const modalTitle = document.getElementById('userModalTitle');
        const form = document.getElementById('userForm');

        if (userId) {
            modalTitle.textContent = 'Benutzer bearbeiten';
            const user = this.users.find(u => u.id === userId);
            if (user) {
                form.username.value = user.username;
                form.email.value = user.email;
                form.first_name.value = user.first_name;
                form.last_name.value = user.last_name;
                form.role_id.value = user.role_id;
                form.is_active.checked = user.is_active;
                
                // Disable username for existing users
                form.username.disabled = true;
                
                // Hide password field for edit
                document.getElementById('passwordGroup').style.display = 'none';
            }
        } else {
            modalTitle.textContent = 'Neuer Benutzer';
            form.reset();
            form.username.disabled = false;
            document.getElementById('passwordGroup').style.display = 'block';
        }

        modal.show();
    }

    async handleUserSubmit(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
        
        const userData = {
            username: formData.get('username'),
            email: formData.get('email'),
            first_name: formData.get('first_name'),
            last_name: formData.get('last_name'),
            role_id: parseInt(formData.get('role_id')),
            is_active: formData.get('is_active') === 'on'
        };

        if (!this.currentEditUser) {
            userData.password = formData.get('password');
        }

        try {
            const response = await authManager.apiRequest(
                this.currentEditUser ? `/users/${this.currentEditUser}` : '/users',
                {
                    method: this.currentEditUser ? 'PUT' : 'POST',
                    body: JSON.stringify(userData)
                }
            );

            if (response.ok) {
                const data = await response.json();
                
                // Show success message
                if (!this.currentEditUser && data.temporary_password) {
                    this.showTempPasswordModal(userData.username, data.temporary_password);
                } else {
                    this.showSuccess(this.currentEditUser ? 'Benutzer aktualisiert' : 'Benutzer erstellt');
                }

                // Close modal and reload users
                bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
                await this.loadUsers();
            } else {
                const error = await response.json();
                this.showError(error.error || 'Fehler beim Speichern');
            }
        } catch (error) {
            console.error('Error saving user:', error);
            this.showError('Fehler beim Speichern des Benutzers');
        }
    }

    async resetPassword(userId) {
        if (!confirm('Möchten Sie das Passwort wirklich zurücksetzen?')) return;

        try {
            const response = await authManager.apiRequest(`/users/${userId}/reset-password`, {
                method: 'POST'
            });

            if (response.ok) {
                const data = await response.json();
                this.showTempPasswordModal('', data.temporary_password);
            } else {
                this.showError('Fehler beim Zurücksetzen des Passworts');
            }
        } catch (error) {
            console.error('Error resetting password:', error);
            this.showError('Fehler beim Zurücksetzen des Passworts');
        }
    }

    async unlockUser(userId) {
        try {
            const response = await authManager.apiRequest(`/users/${userId}/unlock`, {
                method: 'POST'
            });

            if (response.ok) {
                this.showSuccess('Benutzer entsperrt');
                await this.loadUsers();
            }
        } catch (error) {
            console.error('Error unlocking user:', error);
            this.showError('Fehler beim Entsperren des Benutzers');
        }
    }

    async deleteUser(userId) {
        if (!confirm('Möchten Sie diesen Benutzer wirklich löschen?')) return;

        try {
            const response = await authManager.apiRequest(`/users/${userId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showSuccess('Benutzer gelöscht');
                await this.loadUsers();
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            this.showError('Fehler beim Löschen des Benutzers');
        }
    }

    showTempPasswordModal(username, password) {
        const modal = new bootstrap.Modal(document.getElementById('tempPasswordModal'));
        document.getElementById('tempUsername').textContent = username;
        document.getElementById('tempPassword').textContent = password;
        
        // Copy password button
        document.getElementById('copyPasswordBtn').onclick = () => {
            navigator.clipboard.writeText(password);
            this.showSuccess('Passwort kopiert');
        };
        
        modal.show();
    }

    filterUsers(searchTerm) {
        const filteredUsers = this.users.filter(user => {
            const search = searchTerm.toLowerCase();
            return user.username.toLowerCase().includes(search) ||
                   user.email.toLowerCase().includes(search) ||
                   user.first_name.toLowerCase().includes(search) ||
                   user.last_name.toLowerCase().includes(search);
        });
        
        this.users = filteredUsers;
        this.renderUserTable();
        
        if (searchTerm === '') {
            this.loadUsers(); // Reload all users
        }
    }

    filterByRole(roleId) {
        if (roleId === '') {
            this.loadUsers();
        } else {
            const filteredUsers = this.users.filter(user => user.role_id == roleId);
            this.users = filteredUsers;
            this.renderUserTable();
        }
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showError(message) {
        this.showNotification(message, 'danger');
    }

    showNotification(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0 position-fixed bottom-0 end-0 m-3`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
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
const userManagement = new UserManagement();
window.userManagement = userManagement;