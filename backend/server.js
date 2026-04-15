require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const { sql, initDB } = require('./db');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');

const s3 = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
    }
});
const BUCKET_NAME = process.env.R2_BUCKET_NAME;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Must be 32 bytes

if (!JWT_SECRET || !ENCRYPTION_KEY) {
    console.error('FATAL: JWT_SECRET and ENCRYPTION_KEY must be set in environment variables.');
    process.exit(1);
}
const IV_LENGTH = 16;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
    origin: true,
    credentials: true
}));

// === ROUTE PROTECTION: Guard pages BEFORE static serving ===
app.get('/admin.html', (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login.html');
    try {
        const user = jwt.verify(token, JWT_SECRET);
        if (user.role !== 'admin') return res.redirect('/login.html');
        next();
    } catch { return res.redirect('/login.html'); }
});

app.get('/dashboard.html', (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login.html');
    try {
        jwt.verify(token, JWT_SECRET);
        next();
    } catch { return res.redirect('/login.html'); }
});

app.use(express.static(path.join(__dirname, '../frontend')));

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

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const lowerEmail = email.toLowerCase();
    try {
        const rows = await sql`SELECT * FROM users WHERE email = ${lowerEmail}`;
        const user = rows[0];
        if (!user) return res.status(400).json({ error: 'Invalid email or password' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Invalid email or password' });

        const session_id = crypto.randomUUID();
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name, session_id }, JWT_SECRET, { expiresIn: '8h' });
        res.cookie('token', token, { httpOnly: true });
        res.json({ message: 'Logged in successfully', role: user.role });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.clearCookie('admin_token');
    res.json({ message: 'Logged out' });
});

app.get('/api/admin/clients', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const rows = await sql`SELECT u.id, u.email, u.name, c.powerbi_url FROM users u LEFT JOIN client_data c ON u.id = c.client_id WHERE u.role = 'client'`;
        res.json(rows || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/clients', authenticateToken, requireAdmin, async (req, res) => {
    const { name, email, password, powerbi_url } = req.body;
    const lowerEmail = email.toLowerCase();
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        const result = await sql`INSERT INTO users (name, email, password, role) VALUES (${name}, ${lowerEmail}, ${hash}, 'client') RETURNING id`;
        const clientId = result[0].id;
        if (powerbi_url) await sql`INSERT INTO client_data (client_id, powerbi_url) VALUES (${clientId}, ${powerbi_url})`;
        res.json({ message: 'Success', id: clientId });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Email exists.' });
    }
});

app.put('/api/admin/clients/:id', authenticateToken, requireAdmin, async (req, res) => {
    const clientId = parseInt(req.params.id);
    const { powerbi_url } = req.body;
    try {
        const existing = await sql`SELECT id FROM client_data WHERE client_id = ${clientId}`;
        if (existing.length > 0) {
            await sql`UPDATE client_data SET powerbi_url = ${powerbi_url} WHERE client_id = ${clientId}`;
        } else {
            await sql`INSERT INTO client_data (client_id, powerbi_url) VALUES (${clientId}, ${powerbi_url})`;
        }
        res.json({ message: 'Updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Admin resets a client's password
app.put('/api/admin/clients/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPassword, salt);
        const result = await sql`UPDATE users SET password = ${hash} WHERE id = ${parseInt(req.params.id)} AND role = 'client'`;
        if (result.length === 0 && result.count === 0) return res.status(404).json({ error: 'Client not found' });
        res.json({ message: 'Password reset successfully' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

// Self-service password change (verifies current password)
app.put('/api/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'All fields are required.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters.' });

    try {
        const rows = await sql`SELECT * FROM users WHERE id = ${req.user.id}`;
        const user = rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });

        const validPass = await bcrypt.compare(currentPassword, user.password);
        if (!validPass) return res.status(400).json({ error: 'Current password is incorrect.' });

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPassword, salt);
        await sql`UPDATE users SET password = ${hash} WHERE id = ${user.id}`;
        res.json({ message: 'Password changed successfully' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Server error' });
    }
});

// IMPERSONATION LOGIC
app.post('/api/admin/impersonate/:email', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const rows = await sql`SELECT * FROM users WHERE email = ${req.params.email}`;
        const user = rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Cache the true admin's token securely
        res.cookie('admin_token', req.cookies.token, { httpOnly: true });

        const session_id = crypto.randomUUID();
        const clientToken = jwt.sign({ id: user.id, email: user.email, role: 'client', name: user.name, isImpersonating: true, session_id }, JWT_SECRET, { expiresIn: '1h' });

        // Override primary token with client context
        res.cookie('token', clientToken, { httpOnly: true });
        res.json({ message: 'Impersonating' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
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
    try {
        const listData = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET_NAME }));
        if (!listData.Contents) return res.json({message: 'No metadata files found to recover.', recoveredCount: 0});

        const metaFiles = listData.Contents.filter(item => item.Key.endsWith('.meta'));
        if (metaFiles.length === 0) return res.json({message: 'No metadata files found to recover.', recoveredCount: 0});

        let recoveredCount = 0;

        for (const file of metaFiles) {
            try {
                const response = await s3.send(new GetObjectCommand({ Bucket: BUCKET_NAME, Key: file.Key }));
                const fileBuffer = Buffer.from(await response.Body.transformToByteArray());

                const iv = fileBuffer.subarray(0, 16);
                const encryptedData = fileBuffer.subarray(16);

                const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
                let decryptedPayload = decipher.update(encryptedData);
                decryptedPayload = Buffer.concat([decryptedPayload, decipher.final()]);

                const meta = JSON.parse(decryptedPayload.toString('utf8'));

                const existing = await sql`SELECT id FROM documents WHERE filepath = ${meta.filepath}`;
                if (existing.length === 0) {
                    await sql`INSERT INTO documents (client_email, filepath, original_name, category, description, uploaded_by, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type, upload_date) VALUES (${meta.client_email}, ${meta.filepath}, ${meta.original_name}, ${meta.category}, ${meta.description}, ${meta.uploaded_by}, ${'restored'}, ${meta.financial_year}, ${meta.bank_period}, ${meta.bank_account}, ${meta.bank_name}, ${meta.id_proof_type}, ${meta.upload_date})`;
                    recoveredCount++;
                }
            } catch (e) {
                console.error("Error restoring", file.Key, e);
            }
        }
        res.json({message: 'Disaster recovery sweep completed.', recoveredCount});
    } catch (e) {
        console.error(e);
        res.status(500).json({error: 'R2 Sweep failed.'});
    }
});

app.get('/api/client-dashboard', authenticateToken, async (req, res) => {
    const email = req.user.email;
    if (req.user.role === 'admin') return res.status(403).json({error: "Admins should use admin dashboard."});

    try {
        const dataRows = await sql`SELECT powerbi_url FROM client_data WHERE client_id = ${req.user.id}`;
        const docs = await sql`SELECT id, original_name, category, description, upload_date, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type FROM documents WHERE client_email = ${email} ORDER BY upload_date DESC`;
        const creds = await sql`SELECT id, platform_name, username, encrypted_password, notes, last_updated FROM credentials WHERE client_email = ${email}`;

        const decryptedCreds = (creds || []).map(c => {
            let p = '';
            try { p = decrypt(c.encrypted_password); } catch(e) { p = 'DECRYPTION_ERROR'; }
            return { ...c, password: p };
        });

        res.json({
            user: { name: req.user.name, email: email, isImpersonating: !!req.user.isImpersonating, session_id: req.user.session_id },
            powerbi_url: dataRows.length > 0 ? dataRows[0].powerbi_url : null,
            documents: docs || [],
            credentials: decryptedCreds
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

/* --- PHYSICAL FILE ENCRYPTION ROUTE --- */
app.post('/api/documents', authenticateToken, upload.single('file'), async (req, res) => {
    const { client_email, category, description, financial_year, bank_period, bank_account, bank_name, id_proof_type } = req.body;
    let targetEmail = req.user.role === 'client' ? req.user.email : client_email;

    const tmpPath = req.file.path;
    const finalKey = Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '-ENCRYPTED.enc';
    const tmpFinalPath = path.join(uploadDir, finalKey);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);

    const input = fs.createReadStream(tmpPath);
    const output = fs.createWriteStream(tmpFinalPath);
    output.write(iv);
    input.pipe(cipher).pipe(output);

    output.on('finish', async () => {
        try {
            fs.unlink(tmpPath, () => {}); // delete non-encrypted tmp file

            await s3.send(new PutObjectCommand({
                Bucket: BUCKET_NAME,
                Key: finalKey,
                Body: fs.createReadStream(tmpFinalPath)
            }));

            fs.unlink(tmpFinalPath, () => {});

            await sql`INSERT INTO documents (client_email, filepath, original_name, category, description, uploaded_by, session_id, financial_year, bank_period, bank_account, bank_name, id_proof_type) VALUES (${targetEmail}, ${finalKey}, ${req.file.originalname}, ${category || null}, ${description || null}, ${req.user.email}, ${req.user.session_id}, ${financial_year || null}, ${bank_period || null}, ${bank_account || null}, ${bank_name || null}, ${id_proof_type || null})`;

            const metaPayload = JSON.stringify({
                client_email: targetEmail,
                filepath: finalKey,
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

            const metaKey = finalKey.replace('.enc', '.meta');
            const metaIv = crypto.randomBytes(16);
            const metaCipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), metaIv);

            let metaBuffer = metaIv;
            metaBuffer = Buffer.concat([metaBuffer, metaCipher.update(metaPayload, 'utf8')]);
            metaBuffer = Buffer.concat([metaBuffer, metaCipher.final()]);

            await s3.send(new PutObjectCommand({
                Bucket: BUCKET_NAME,
                Key: metaKey,
                Body: metaBuffer
            }));

            res.json({ message: 'Uploaded and Encrypted successfully' });
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: 'R2 Upload failed' });
        }
    });
});

/* --- PHYSICAL FILE DECRYPTION ROUTE --- */
app.get('/api/documents/:id/download', authenticateToken, async (req, res) => {
    try {
        const rows = await sql`SELECT * FROM documents WHERE id = ${parseInt(req.params.id)}`;
        const row = rows[0];
        if (!row || !row.filepath) return res.status(404).send('Not found or Corrupt');
        if (req.user.role === 'client' && row.client_email !== req.user.email) return res.status(403).send('Unauthorized');

        // BACKWARD COMPATIBILITY: Legacy Local Files
        if (row.filepath.includes('/') || row.filepath.includes('\\')) {
            if (!fs.existsSync(row.filepath)) return res.status(404).send('Local file missing');
            const fd = fs.openSync(row.filepath, 'r');
            const iv = Buffer.alloc(16);
            fs.readSync(fd, iv, 0, 16, 0);
            fs.closeSync(fd);

            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
            res.attachment(row.original_name);
            return fs.createReadStream(row.filepath, { start: 16 }).pipe(decipher).pipe(res);
        }

        const ivResponse = await s3.send(new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: row.filepath,
            Range: 'bytes=0-15'
        }));
        const ivArrayBuffer = await ivResponse.Body.transformToByteArray();
        const iv = Buffer.from(ivArrayBuffer);

        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        res.attachment(row.original_name);

        const fileResponse = await s3.send(new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: row.filepath,
            Range: 'bytes=16-'
        }));

        fileResponse.Body.pipe(decipher).pipe(res);
    } catch (e) {
        console.error(e);
        res.status(500).send('Error decrypting file.');
    }
});

app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const rows = await sql`SELECT * FROM documents WHERE id = ${parseInt(req.params.id)}`;
        const row = rows[0];
        if (!row) return res.status(404).json({error: 'Not found'});
        if (req.user.role === 'client') {
            if (row.session_id !== req.user.session_id && !req.user.isImpersonating) {
                return res.status(403).json({error: 'Cannot delete files outside of session.'});
            }
        }

        await sql`DELETE FROM documents WHERE id = ${parseInt(req.params.id)}`;

        if (row.filepath.includes('/') || row.filepath.includes('\\')) {
            fs.unlink(row.filepath, () => {});
            fs.unlink(row.filepath.replace('.enc', '.meta'), () => {});
        } else {
            try {
                await s3.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: row.filepath }));
                await s3.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: row.filepath.replace('.enc', '.meta') }));
            } catch (e) {
                console.error("Failed to delete from R2:", e);
            }
        }
        res.json({message: 'Deleted'});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/credentials', authenticateToken, requireAdmin, async (req, res) => {
    const { client_email, platform_name, username, password, notes } = req.body;
    const encrypted = encrypt(password);
    try {
        await sql`INSERT INTO credentials (client_email, platform_name, username, encrypted_password, notes) VALUES (${client_email}, ${platform_name}, ${username}, ${encrypted}, ${notes || null})`;
        res.json({message: 'Saved'});
    } catch (err) {
        console.error(err);
        res.status(500).json({error: 'DB error'});
    }
});

app.put('/api/credentials/:id', authenticateToken, requireAdmin, async (req, res) => {
    const { platform_name, username, password, notes } = req.body;
    try {
        if (password) {
            const encrypted = encrypt(password);
            await sql`UPDATE credentials SET platform_name = ${platform_name}, username = ${username}, notes = ${notes || null}, encrypted_password = ${encrypted}, last_updated = NOW() WHERE id = ${parseInt(req.params.id)}`;
        } else {
            await sql`UPDATE credentials SET platform_name = ${platform_name}, username = ${username}, notes = ${notes || null}, last_updated = NOW() WHERE id = ${parseInt(req.params.id)}`;
        }
        res.json({message: 'Updated'});
    } catch (err) {
        console.error(err);
        res.status(500).json({error: 'DB error'});
    }
});

// Initialize DB and start server
initDB().then(() => {
    if (process.env.VERCEL) {
        module.exports = app;
    } else {
        app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
    }
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});

// For Vercel — export app immediately but DB inits async
if (process.env.VERCEL) {
    module.exports = app;
}
