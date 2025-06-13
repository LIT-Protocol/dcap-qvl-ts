import forge from 'node-forge';

// Generate a random 16-byte key
const key = forge.random.getBytesSync(16);
console.log('Generated key (hex):', forge.util.bytesToHex(key));

// Example plaintext
const plaintext = 'Hello, node-forge!';
console.log('Plaintext:', plaintext);

// Encrypt the plaintext using AES-CBC
const iv = forge.random.getBytesSync(16);
const cipher = forge.cipher.createCipher('AES-CBC', key);
cipher.start({ iv });
cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
cipher.finish();
const encrypted = cipher.output.getBytes();
console.log('Encrypted (hex):', forge.util.bytesToHex(forge.util.createBuffer(encrypted).bytes()));

// Decrypt the ciphertext
const decipher = forge.cipher.createDecipher('AES-CBC', key);
decipher.start({ iv });
decipher.update(forge.util.createBuffer(encrypted));
decipher.finish();
const decrypted = decipher.output.toString();
console.log('Decrypted:', decrypted);
