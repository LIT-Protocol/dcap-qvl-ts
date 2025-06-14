import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keyPath = path.join(__dirname, 'ecdsa-key.pem');
const certPath = path.join(__dirname, 'ecdsa-cert.pem');

try {
  // Generate ECDSA private key
  execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${keyPath}`);
  // Generate self-signed certificate
  execSync(
    `openssl req -new -x509 -key ${keyPath} -out ${certPath} -days 365 -subj "/CN=ECDSA Test"`,
  );
  const certPem = fs.readFileSync(certPath, 'utf8');
  console.log('Certificate PEM:\n', certPem);
  console.log('Private key PEM written to:', keyPath);
  console.log('Certificate PEM written to:', certPath);
} catch (err) {
  console.error('OpenSSL error:', err.stderr ? err.stderr.toString() : err);
  process.exit(1);
}
