const http = require('http');
const fs = require('fs');

const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('portal.db');

db.get('SELECT * FROM users WHERE email = ?', ['harismtkiz91@gmail.com'], (err, user) => {
    // Generate a temporary JWT token just for this test script
    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ id: user.id, email: user.email, role: 'client', name: user.name, session_id: '123' }, 'super_secret_hyandco_key_123', { expiresIn: '1h' });

    console.log("Simulating download...");
    const req = http.request({
        hostname: 'localhost',
        port: 3000,
        path: '/api/documents/1/download',
        method: 'GET',
        headers: { 'Cookie': `token=${token}` }
    }, (res) => {
        console.log("HTTP Code:", res.statusCode);
        const out = fs.createWriteStream('downloaded-test.pdf');
        res.pipe(out);
        out.on('finish', () => {
            const stats = fs.statSync('downloaded-test.pdf');
            console.log("Downloaded size:", stats.size);
        });
    });
    req.end();
});
