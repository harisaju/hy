const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const ENCRYPTION_KEY = '12345678901234567890123456789012';

// 1. Create a dummy original text file
fs.writeFileSync('dummy.txt', 'Hello this is a test file.');

// 2. Encrypt it
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
const input = fs.createReadStream('dummy.txt');
const output = fs.createWriteStream('dummy.enc');
output.write(iv);
input.pipe(cipher).pipe(output);

output.on('finish', () => {
    console.log('Encrypted to dummy.enc');
    
    // 3. Decrypt it
    const fd = fs.openSync('dummy.enc', 'r');
    const readIv = Buffer.alloc(16);
    fs.readSync(fd, readIv, 0, 16, 0);
    fs.closeSync(fd);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), readIv);
    const decInput = fs.createReadStream('dummy.enc', { start: 16 });
    const decOutput = fs.createWriteStream('dummy-dec.txt');
    
    decInput.pipe(decipher).pipe(decOutput);
    
    decOutput.on('finish', () => {
        console.log('Decrypted to dummy-dec.txt');
        const result = fs.readFileSync('dummy-dec.txt', 'utf8');
        console.log('Result:', result);
    });
});
