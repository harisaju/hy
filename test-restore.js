const fs = require('fs');
const sqlite3 = require('sqlite3');
const path = require('path');
const db = new sqlite3.Database('portal.db');

const files = fs.readdirSync(path.join(__dirname, 'uploads')).filter(f => f.endsWith('.enc'));

files.forEach((file, index) => {
    const finalPath = path.join(__dirname, 'uploads', file);
    db.run(`INSERT INTO documents (client_email, filepath, original_name, category, description, uploaded_by, session_id, financial_year) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
        ['harismtkiz91@gmail.com', finalPath, `Restored_File_${index+1}.pdf`, 'Other Documents', 'Manually restored', 'admin', 'restored_session', 'FY 2024-25'], function(err) {
            if (err) console.error(err);
            else console.log(`Restored ${file}`);
        });
});
