const BetterSQLite3 = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class Database {
    constructor() {
        this.db = null;
        this.dbPath = path.join(__dirname, 'foodsuite.db');
    }

    async initialize() {
        return new Promise((resolve, reject) => {
            // Create database directory if it doesn't exist
            const dbDir = path.dirname(this.dbPath);
            if (!fs.existsSync(dbDir)) {
                fs.mkdirSync(dbDir, { recursive: true });
            }

            // Connect to database
            this.db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    console.error('Error opening database:', err);
                    reject(err);
                } else {
                    console.log('📊 Connected to SQLite database');
                    this.createTables()
                        .then(() => resolve())
                        .catch(reject);
                }
            });

            // Enable foreign key constraints
            this.db.run('PRAGMA foreign_keys = ON');
        });
    }

    async createTables() {
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');
        
        return new Promise((resolve, reject) => {
            this.db.exec(schema, (err) => {
                if (err) {
                    console.error('Error creating tables:', err);
                    reject(err);
                } else {
                    console.log('✅ Database tables created successfully');
                    resolve();
                }
            });
        });
    }

    // Generic query method
    async query(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    console.error('Database query error:', err);
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    // Generic run method for INSERT, UPDATE, DELETE
    async run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    console.error('Database run error:', err);
                    reject(err);
                } else {
                    resolve({
                        lastID: this.lastID,
                        changes: this.changes
                    });
                }
            });
        });
    }

    // Get single row
    async get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) {
                    console.error('Database get error:', err);
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    // Transaction support
    async transaction(callback) {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                this.db.run('BEGIN TRANSACTION');
                
                Promise.resolve(callback(this))
                    .then(result => {
                        this.db.run('COMMIT', (err) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(result);
                            }
                        });
                    })
                    .catch(error => {
                        this.db.run('ROLLBACK', () => {
                            reject(error);
                        });
                    });
            });
        });
    }

    // Close database connection
    close() {
        return new Promise((resolve, reject) => {
            if (this.db) {
                this.db.close((err) => {
                    if (err) {
                        console.error('Error closing database:', err);
                        reject(err);
                    } else {
                        console.log('📊 Database connection closed');
                        resolve();
                    }
                });
            } else {
                resolve();
            }
        });
    }

    // Helper methods for common operations
    async findById(table, id, tenantId = null) {
        const whereClause = tenantId ? 
            `WHERE id = ? AND tenant_id = ?` : 
            `WHERE id = ?`;
        const params = tenantId ? [id, tenantId] : [id];
        
        const sql = `SELECT * FROM ${table} ${whereClause}`;
        return await this.get(sql, params);
    }

    async findAll(table, tenantId = null, options = {}) {
        let sql = `SELECT * FROM ${table}`;
        let params = [];

        if (tenantId) {
            sql += ` WHERE tenant_id = ?`;
            params.push(tenantId);
        }

        if (options.where) {
            sql += tenantId ? ` AND ${options.where}` : ` WHERE ${options.where}`;
            if (options.params) {
                params = params.concat(options.params);
            }
        }

        if (options.orderBy) {
            sql += ` ORDER BY ${options.orderBy}`;
        }

        if (options.limit) {
            sql += ` LIMIT ?`;
            params.push(options.limit);
        }

        if (options.offset) {
            sql += ` OFFSET ?`;
            params.push(options.offset);
        }

        return await this.query(sql, params);
    }

    async create(table, data) {
        const columns = Object.keys(data).join(', ');
        const placeholders = Object.keys(data).map(() => '?').join(', ');
        const values = Object.values(data);

        const sql = `INSERT INTO ${table} (${columns}) VALUES (${placeholders})`;
        const result = await this.run(sql, values);
        
        return await this.get(`SELECT * FROM ${table} WHERE id = ?`, [result.lastID]);
    }

    async update(table, id, data, tenantId = null) {
        const columns = Object.keys(data).map(col => `${col} = ?`).join(', ');
        const values = Object.values(data);
        
        let sql = `UPDATE ${table} SET ${columns}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
        let params = [...values, id];

        if (tenantId) {
            sql += ` AND tenant_id = ?`;
            params.push(tenantId);
        }

        await this.run(sql, params);
        return await this.findById(table, id, tenantId);
    }

    async delete(table, id, tenantId = null) {
        let sql = `DELETE FROM ${table} WHERE id = ?`;
        let params = [id];

        if (tenantId) {
            sql += ` AND tenant_id = ?`;
            params.push(tenantId);
        }

        const result = await this.run(sql, params);
        return result.changes > 0;
    }

    // Search functionality
    async search(table, searchFields, searchTerm, tenantId = null) {
        const searchConditions = searchFields.map(field => 
            `${field} LIKE ?`
        ).join(' OR ');
        
        let sql = `SELECT * FROM ${table}`;
        let params = [];

        if (tenantId) {
            sql += ` WHERE tenant_id = ? AND (${searchConditions})`;
            params.push(tenantId);
            searchFields.forEach(() => params.push(`%${searchTerm}%`));
        } else {
            sql += ` WHERE (${searchConditions})`;
            searchFields.forEach(() => params.push(`%${searchTerm}%`));
        }

        return await this.query(sql, params);
    }

    // Pagination helper
    async paginate(table, page = 1, limit = 10, tenantId = null, options = {}) {
        const offset = (page - 1) * limit;
        
        // Get total count
        let countSql = `SELECT COUNT(*) as count FROM ${table}`;
        let countParams = [];
        
        if (tenantId) {
            countSql += ` WHERE tenant_id = ?`;
            countParams.push(tenantId);
        }

        if (options.where) {
            countSql += tenantId ? ` AND ${options.where}` : ` WHERE ${options.where}`;
            if (options.params) {
                countParams = countParams.concat(options.params);
            }
        }

        const countResult = await this.get(countSql, countParams);
        const totalItems = countResult.count;
        const totalPages = Math.ceil(totalItems / limit);

        // Get paginated results
        const items = await this.findAll(table, tenantId, {
            ...options,
            limit,
            offset
        });

        return {
            items,
            pagination: {
                page,
                limit,
                totalItems,
                totalPages,
                hasNextPage: page < totalPages,
                hasPreviousPage: page > 1
            }
        };
    }
}

// Create singleton instance
const database = new Database();

module.exports = database;