const BetterSQLite3 = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class Database {
    constructor() {
        this.db = null;
        this.dbPath = path.join(__dirname, 'foodsuite.db');
    }

    initialize() {
        try {
            // Create database directory if it doesn't exist
            const dbDir = path.dirname(this.dbPath);
            if (!fs.existsSync(dbDir)) {
                fs.mkdirSync(dbDir, { recursive: true });
            }

            // Connect to database
            this.db = new BetterSQLite3(this.dbPath);
            console.log('📊 Connected to SQLite database');
            
            // Enable foreign key constraints
            this.db.pragma('foreign_keys = ON');
            
            this.createTables();
            
            return Promise.resolve();
        } catch (error) {
            console.error('Error initializing database:', error);
            return Promise.reject(error);
        }
    }

    createTables() {
        try {
            const schemaPath = path.join(__dirname, 'schema.sql');
            const schema = fs.readFileSync(schemaPath, 'utf8');
            
            this.db.exec(schema);
            console.log('✅ Database tables created successfully');
        } catch (error) {
            console.error('Error creating tables:', error);
            throw error;
        }
    }

    // Generic query method
    query(sql, params = []) {
        try {
            const stmt = this.db.prepare(sql);
            const result = stmt.all(params);
            return Promise.resolve(result);
        } catch (error) {
            console.error('Database query error:', error);
            return Promise.reject(error);
        }
    }

    // Generic run method for INSERT, UPDATE, DELETE
    run(sql, params = []) {
        try {
            const stmt = this.db.prepare(sql);
            const result = stmt.run(params);
            return Promise.resolve({
                lastID: result.lastInsertRowid,
                changes: result.changes
            });
        } catch (error) {
            console.error('Database run error:', error);
            return Promise.reject(error);
        }
    }

    // Get single row
    get(sql, params = []) {
        try {
            const stmt = this.db.prepare(sql);
            const result = stmt.get(params);
            return Promise.resolve(result);
        } catch (error) {
            console.error('Database get error:', error);
            return Promise.reject(error);
        }
    }

    // Transaction support
    transaction(callback) {
        try {
            const result = this.db.transaction(() => {
                return callback(this);
            })();
            return Promise.resolve(result);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // Close database connection
    close() {
        try {
            if (this.db) {
                this.db.close();
                console.log('📊 Database connection closed');
            }
            return Promise.resolve();
        } catch (error) {
            console.error('Error closing database:', error);
            return Promise.reject(error);
        }
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