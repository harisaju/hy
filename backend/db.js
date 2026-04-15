const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');

const sql = neon(process.env.DATABASE_URL);

async function initDB() {
    console.log('Connecting to Neon PostgreSQL...');

    await sql`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        password TEXT,
        name TEXT,
        role TEXT
    )`;

    await sql`CREATE TABLE IF NOT EXISTS client_data (
        id SERIAL PRIMARY KEY,
        client_id INTEGER REFERENCES users(id),
        powerbi_url TEXT,
        notes TEXT
    )`;

    await sql`CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
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
        upload_date TIMESTAMPTZ DEFAULT NOW()
    )`;

    await sql`CREATE TABLE IF NOT EXISTS credentials (
        id SERIAL PRIMARY KEY,
        client_email TEXT,
        platform_name TEXT,
        username TEXT,
        encrypted_password TEXT,
        notes TEXT,
        last_updated TIMESTAMPTZ DEFAULT NOW()
    )`;

    // Seed default admin if none exists
    const admins = await sql`SELECT * FROM users WHERE role = 'admin'`;
    if (admins.length === 0) {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash('admin123', salt);
        await sql`INSERT INTO users (email, password, name, role) VALUES ('ca.hyandco@gmail.com', ${hash}, 'Haris Yoonus Admin', 'admin')`;
        console.log('Default admin seeded: ca.hyandco@gmail.com / admin123');
    }

    console.log('Neon PostgreSQL initialized successfully.');
}

module.exports = { sql, initDB };
