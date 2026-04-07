require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_hyandco_key_123';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; // Must be 32 bytes
const IV_LENGTH = 16;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const uploadDir = process.env.VERCEL ? '/tmp/uploads' : path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => cb(null, 'tmp-' + Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Crypto Functions for Credentials (Text)
function encrypt(text) {
    if (!text) return text;
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return text;
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
};

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const lowerEmail = email.toLowerCase();
    db.get(`SELECT * FROM users WHERE email = ?`, [lowerEmail], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid email or password' });
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Invalid email or password' });

        const session_id = crypto.randomUUID();
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name, session_id }, JWT_SECRET, { expiresIn: '8h' });
        res.cookie('token', token, { httpOnly: true });
        res.json({ message: 'Logged in successfully', role: user.role });
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.clearCookie('admin_token');
    res.json({ message: 'Logged out' });
});

app.get('/api/admin/clients', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT u.id, u.email, u.name, c.powerbi_url FROM users u LEFT JOIN client_data c ON u.id = c.client_id WHERE u.role = 'client'`, [], (err, rows) => {
        res.json(rows || []);
    });
});

app.post('/api/admin/clients', authenticateToken, requireAdmin, async (req, res) => {
    const { name, email, password, powerbi_url } = req.body;
    const lowerEmail = email.toLowerCase();
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        db.run(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'client')`, [name, lowerEmail, hash], function(err) {
            if (err) return res.status(400).json({ error: 'Email exists.' });
            const clientId = this.lastID;
            if (powerbi_url) db.run(`INSERT INTO client_data (client_id, powerbi_url) VALUES (?, ?)`, [clientId, powerbi_url]);
            res.json({ message: 'Success', id: clientId });
        });
    } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/clients/:id', authenticateToken, requireAdmin, (req, res) => {
    const clientId = req.params.id;
    const { powerbi_url } = req.body;
    db.get(`SELECT id FROM client_data WHERE client_id = ?`, [clientId], (err, row) => {
        if (row) db.run(`UPDATE client_data SET powerbi_url = ? WHERE client_id = ?`, [powerbi_url, clientId]);
        else db.run(`INSERT INTO client_data (client_id, powerbi_url) VALUES (?, ?)`, [clientId, powerbi_url]);
        res.json({ message: 'Updated' });
    });
});

// IMPERSONATION LOGIC
app.post('/api/admin/impersonate/:email', authenticateToken, requireAdmin, (req, res) => {
    db.get(`SELECT * FROM users WHERE email = ?`, [req.params.email], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });
        
        // Cache the true admin's token securely
        res.cookie('admin_token', req.cookies.token, { httpOnly: true });

        const session_id = crypto.randomUUID();
        const clientToken = jwt.sign({ id: user.id, email: user.email, role: 'client', name: user.name, isImpersonating: true, session_id }, JWT_SECRET, { expiresIn: '1h' });
        
        // Override primary token with client context
        res.cookie('token', clientToken, { httpOnly: true });
        res.json({ message: 'Impersonating' });
    });
});

app.post('/api/admin/exit-impersonation', (req, res) => {
    const adminToken = req.cookies.admin_token;
    if (!adminToken) return res.status(400).json({error: 'No active impersonation context.'});
    
    // Verify admin token is legitimately an admin
    jwt.verify(adminToken, JWT_SECRET, (err, user) => {
        if (err || user.role !== 'admin') return res.status(403).json({ error: 'Invalid admin context' });
        
        // Restore session
        res.cookie('token', adminToken, { httpOnly: true });
        res.clearCookie('admin_token');
        res.json({ message: 'Restored Admin Session' });
    });
});

app.post('/api/admin/system/disaster-recovery', authenticateToken, requireAdmin, async (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) return res.status(500).json({error: 'Directory sweep failed.'});
        
        const metaFiles = files.filter(f => f.endsWith('.meta'));
        let recoveredCount = 0;
        let processedCount = 0;
        
        if (metaFiles.length === 0) return res.json({message: 'No metadata files found to recover.', recoveredCount: 0});
        
        metaFiles.forEach(file => {
            const metaPath = path.join(uploadDir, file);
            try {
                const fd = fs.openSync(metaPath, 'r');
                const iv = Buffer.alloc(16);
                fs.readSync(fd, iv, 0, 16, 0);
                fs.closeSync(fd);
                
                const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
                let outputBuffer = Buffer.alloc(0);
                const readStream = fs.createReadStream(metaPath, { start: 16 });
                
                decipher.on('data', (d) => { outputBuffer = Buffer.concat([outputBuffer, d]); });
                decipher.on('end', () => {
                    try {
                        const meta = JSON.parse(outputBuffer.toString());
                        db.get("SELECT id FROM documents WHERE filepath = ?", [meta.filepath], (err, row) => {
                            if (!row) {
                                db.run(`INSERT INTO documents (client_email, filepath, original_name, category, description, uploaded_by, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type, upload_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
                                    [meta.client_email, meta.filepath, meta.original_name, meta.category, meta.description, meta.uploaded_by, 'restored', meta.financial_year, meta.bank_period, meta.bank_account, meta.bank_name, meta.id_proof_type, meta.upload_date], 
                                    () => { recoveredCount++; completeCheck(); }
                                );
                            } else completeCheck();
                        });
                    } catch(e) { completeCheck(); }
                });
                
                readStream.pipe(decipher);
            } catch(e) { completeCheck(); }
            
            function completeCheck() {
                processedCount++;
                if (processedCount === metaFiles.length) {
                    res.json({message: 'Disaster recovery sweep completed.', recoveredCount});
                }
            }
        });
    });
});

app.get('/api/client-dashboard', authenticateToken, (req, res) => {
    const email = req.user.email;
    if (req.user.role === 'admin') return res.status(403).json({error: "Admins should use admin dashboard."});
    
    db.get(`SELECT powerbi_url FROM client_data WHERE client_id = ?`, [req.user.id], (err, dataRow) => {
        db.all(`SELECT id, original_name, category, description, upload_date, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type FROM documents WHERE client_email = ? ORDER BY upload_date DESC`, [email], (err, docs) => {
            db.all(`SELECT id, platform_name, username, encrypted_password, notes, last_updated FROM credentials WHERE client_email = ?`, [email], (err, creds) => {
                
                const decryptedCreds = (creds || []).map(c => {
                    let p = '';
                    try { p = decrypt(c.encrypted_password); } catch(e) { p = 'DECRYPTION_ERROR'; }
                    return { ...c, password: p };
                });

                res.json({
                    user: { name: req.user.name, email: email, isImpersonating: !!req.user.isImpersonating, session_id: req.user.session_id },
                    powerbi_url: dataRow ? dataRow.powerbi_url : null,
                    documents: docs || [],
                    credentials: decryptedCreds
                });
            });
        });
    });
});

/* --- PHYSICAL FILE ENCRYPTION ROUTE --- */
app.post('/api/documents', authenticateToken, upload.single('file'), (req, res) => {
    const { client_email, category, description, financial_year, bank_period, bank_account, bank_name, id_proof_type } = req.body;
    let targetEmail = req.user.role === 'client' ? req.user.email : client_email; 

    // Dynamic File Streaming
    const tmpPath = req.file.path;
    const finalPath = path.join(uploadDir, Date.now() + '-ENCRYPTED.enc');
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    
    const input = fs.createReadStream(tmpPath);
    const output = fs.createWriteStream(finalPath);
    
    // Write IV to opening bytes of the physical file so it carries its own lock!
    output.write(iv);

    input.pipe(cipher).pipe(output);
    
    output.on('finish', () => {
        fs.unlink(tmpPath, () => {}); // delete non-encrypted tmp file

        db.run(`INSERT INTO documents (client_email, filepath, original_name, category, description, uploaded_by, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, 
            [targetEmail, finalPath, req.file.originalname, category, description, req.user.email, req.user.session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type], 
            function(err) {
                if (err) return res.status(500).json({ error: 'Database error' });
                
                // Write encrypted Meta file
                const metaPayload = JSON.stringify({
                    client_email: targetEmail,
                    filepath: finalPath,
                    original_name: req.file.originalname,
                    category: category || null,
                    description: description || null,
                    uploaded_by: req.user.email,
                    financial_year: financial_year || null,
                    bank_period: bank_period || null,
                    bank_account: bank_account || null,
                    bank_name: bank_name || null,
                    id_proof_type: id_proof_type || null,
                    upload_date: new Date().toISOString()
                });
                
                const metaPath = finalPath.replace('.enc', '.meta');
                const metaIv = crypto.randomBytes(16);
                const metaCipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), metaIv);
                
                const metaOutput = fs.createWriteStream(metaPath);
                metaOutput.write(metaIv);
                
                metaCipher.pipe(metaOutput);
                metaCipher.write(metaPayload);
                metaCipher.end();
                
                metaOutput.on('finish', () => res.json({ message: 'Uploaded and Encrypted successfully' }));
        });
    });
});

/* --- PHYSICAL FILE DECRYPTION ROUTE --- */
app.get('/api/documents/:id/download', authenticateToken, (req, res) => {
    db.get(`SELECT * FROM documents WHERE id = ?`, [req.params.id], (err, row) => {
        if (!row || !fs.existsSync(row.filepath)) return res.status(404).send('Not found or Corrupt');
        if (req.user.role === 'client' && row.client_email !== req.user.email) return res.status(403).send('Unauthorized');
        
        try {
            // Read exactly 16 bytes for the IV
            const fd = fs.openSync(row.filepath, 'r');
            const iv = Buffer.alloc(16);
            fs.readSync(fd, iv, 0, 16, 0);
            fs.closeSync(fd);
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
            res.attachment(row.original_name); // Safely computes correct filename encoding + MIME type
            
            // Stream the rest of the file directly through AES Decipher
            fs.createReadStream(row.filepath, { start: 16 }).pipe(decipher).pipe(res);
        } catch (e) {
            console.error(e);
            res.status(500).send('Error decrypting file.');
        }
    });
});

app.delete('/api/documents/:id', authenticateToken, (req, res) => {
    db.get(`SELECT * FROM documents WHERE id = ?`, [req.params.id], (err, row) => {
        if (!row) return res.status(404).json({error: 'Not found'});
        if (req.user.role === 'client') {
            if (row.session_id !== req.user.session_id && !req.user.isImpersonating) { // IsImpersonating allows admin delete
                return res.status(403).json({error: 'Cannot delete files outside of session.'});
            }
        }
        db.run(`DELETE FROM documents WHERE id = ?`, [req.params.id], (err) => {
            if (err) return res.status(500).json({error: 'DB error'});
            fs.unlink(row.filepath, () => {});
            fs.unlink(row.filepath.replace('.enc', '.meta'), () => {});
            res.json({message: 'Deleted'});
        });
    });
});

app.post('/api/credentials', authenticateToken, requireAdmin, (req, res) => {
    const { client_email, platform_name, username, password, notes } = req.body;
    const encrypted = encrypt(password);
    db.run(`INSERT INTO credentials (client_email, platform_name, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)`,
        [client_email, platform_name, username, encrypted, notes], function(err) {
            if(err) return res.status(500).json({error: 'DB error'});
            res.json({message: 'Saved'});
    });
});

app.put('/api/credentials/:id', authenticateToken, requireAdmin, (req, res) => {
    const { platform_name, username, password, notes } = req.body;
    let query = `UPDATE credentials SET platform_name=?, username=?, notes=?, last_updated=CURRENT_TIMESTAMP`;
    let params = [platform_name, username, notes];
    
    if (password) {
        query += `, encrypted_password=?`;
        params.push(encrypt(password));
    }
    query += ` WHERE id=?`;
    params.push(req.params.id);

    db.run(query, params, function(err) { res.json({message: 'Updated'}); });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
