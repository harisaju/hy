const fs = require('fs');
const http = require('http');

// A debug endpoint
console.log("Checking DB records...");
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('portal.db');
db.all("SELECT * FROM documents", (err, rows) => {
    console.log("Documents in DB:", rows.length);
    if (rows.length > 0) {
        const doc = rows[0];
        console.log(doc);
        const stats = fs.statSync(doc.filepath);
        console.log("File size on disk:", stats.size);
        
        const fd = fs.openSync(doc.filepath, 'r');
        const iv = Buffer.alloc(16);
        fs.readSync(fd, iv, 0, 16, 0);
        console.log("IV Extracted:", iv.toString('hex'));
        
        const content = Buffer.alloc(stats.size - 16);
        fs.readSync(fd, content, 0, stats.size - 16, 16);
        fs.closeSync(fd);
        
        console.log("Content size:", content.length);
        
        // Attempt decryption manually
        const crypto = require('crypto');
        try {
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from('12345678901234567890123456789012'), iv);
            let decrypted = decipher.update(content);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            console.log("Successfully decrypted offline! Valid file!");
            console.log("Decrypted size:", decrypted.length);
            
        } catch(e) {
            console.log("Decryption failed offline:", e);
        }
    }
});
