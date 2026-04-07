const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = process.env.VERCEL ? '/tmp/portal.db' : path.resolve(__dirname, 'portal.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                name TEXT,
                role TEXT -- 'admin' or 'client'
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS client_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER,
                powerbi_url TEXT,
                notes TEXT,
                FOREIGN KEY (client_id) REFERENCES users (id)
            )`);
            
            db.run(`CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_email TEXT,
                filepath TEXT,
                original_name TEXT,
                category TEXT,
                description TEXT,
                uploaded_by TEXT,
                session_id TEXT,
                financial_year TEXT,
                bank_period TEXT,
                bank_account TEXT,
                bank_name TEXT,
                id_proof_type TEXT,
                upload_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_email TEXT,
                platform_name TEXT,
                username TEXT,
                encrypted_password TEXT,
                notes TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            
            db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
                if (!row) {
                    const salt = await bcrypt.genSalt(10);
                    const hash = await bcrypt.hash('admin123', salt);
                    db.run(`INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)`, 
                        ['ca.hyandco@gmail.com', hash, 'Haris Yoonus Admin', 'admin']);
                    console.log('Default admin seeded: ca.hyandco@gmail.com / admin123');
                }
            });
        });
    }
});

module.exports = db;
