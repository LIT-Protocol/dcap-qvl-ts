import { generateKeyPairSync, createSign } from 'crypto';
import fs from 'fs';
import asn1 from 'asn1.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Generate ECDSA P-256 keypair
const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Message
const message = 'hello world';

// Sign the message (DER encoded signature)
const sign = createSign('sha256');
sign.update(message);
sign.end();
const sigDer = sign.sign(privateKey); // Buffer

// Convert DER signature to raw r||s (using asn1.js)
const EcdsaSig = asn1.define('EcdsaSig', function () {
  this.seq().obj(this.key('r').int(), this.key('s').int());
});
const decoded = EcdsaSig.decode(sigDer, 'der');
const r = Buffer.from(decoded.r.toArray('be', 32));
const s = Buffer.from(decoded.s.toArray('be', 32));
const sigRaw = Buffer.concat([r, s]);

// Write outputs to the same directory as this script
fs.writeFileSync(path.join(__dirname, 'ecdsa-pub.pem'), publicKey);
fs.writeFileSync(path.join(__dirname, 'ecdsa-message.txt'), message);
fs.writeFileSync(path.join(__dirname, 'ecdsa-sig-raw.hex'), sigRaw.toString('hex'));
fs.writeFileSync(path.join(__dirname, 'ecdsa-sig-der.hex'), sigDer.toString('hex'));

console.log('Public key PEM:\n', publicKey);
console.log('Message:', message);
console.log('Signature (raw r||s, hex):', sigRaw.toString('hex'));
console.log('Signature (DER, hex):', sigDer.toString('hex'));
