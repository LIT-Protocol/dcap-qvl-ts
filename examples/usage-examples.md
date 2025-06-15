# dcap-js Usage Examples

This guide demonstrates how to use the dcap-js public API for Intel SGX/TDX quote verification and parsing.

## 1. Basic Quote Verification (with Provided Collateral)

```js
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';
import fs from 'fs';
import path from 'path';

const quotePath = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  '../dcap-qvl-rust/sample/sgx_quote',
);
const collateralPath = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  '../dcap-qvl-rust/sample/sgx_quote_collateral.json',
);
const quoteBytes = fs.readFileSync(quotePath);
const rawCollateral = JSON.parse(fs.readFileSync(collateralPath, 'utf8'));
const collateral = {
  tcbInfoIssuerChain: rawCollateral.tcb_info_issuer_chain,
  tcbInfo: rawCollateral.tcb_info,
  tcbInfoSignature: Buffer.from(rawCollateral.tcb_info_signature, 'hex'),
  qeIdentityIssuerChain: rawCollateral.qe_identity_issuer_chain,
  qeIdentity: rawCollateral.qe_identity,
  qeIdentitySignature: Buffer.from(rawCollateral.qe_identity_signature, 'hex'),
};

const verifier = new DcapVerifier();
const result = await verifier.verifyQuote(quoteBytes, collateral);
console.log('Verification result:', result);
```

---

## 2. Automatic Collateral Fetching

```js
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';
import fs from 'fs';
import path from 'path';

const quotePath = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  '../dcap-qvl-rust/sample/sgx_quote',
);
const quoteBytes = fs.readFileSync(quotePath);

const verifier = new DcapVerifier({
  // Optionally set PCCS URL, timeouts, etc.
  // pccsUrl: 'https://localhost:8081/sgx/certification/v4',
});
try {
  const result = await verifier.verifyQuote(quoteBytes);
  console.log('Verification result:', result);
} catch (err) {
  console.error('Verification failed:', err);
}
```

---

## 3. Custom Verification Options

```js
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';
const verifier = new DcapVerifier({
  pccsUrl: 'https://localhost:8081/sgx/certification/v4',
  timeout: 10000,
  retries: 2,
  useIntelPCS: false,
  cacheResults: true,
});
// ... use as above
```

---

## 4. Quote Parsing Without Verification

```js
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';
import fs from 'fs';
import path from 'path';

const quotePath = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  '../dcap-qvl-rust/sample/sgx_quote',
);
const quoteBytes = fs.readFileSync(quotePath);

const verifier = new DcapVerifier();
const parsed = verifier.parseQuote(quoteBytes);
console.log('Parsed quote:', parsed);
```

---

## 5. Error Handling Example

```js
import { DcapVerifier } from '@lit-protocol/dcap-qvl-ts';
const verifier = new DcapVerifier();
try {
  // Intentionally pass a malformed quote
  await verifier.verifyQuote(Buffer.from([1, 2, 3]));
} catch (err) {
  console.error('Expected error:', err.message);
}
```

---

## 6. Working with Different Quote Formats

- The API supports both SGX and TDX quotes (V3, V4, V5). Use the same methods as above.
- For TDX, set `isTdx: true` in options if needed for collateral fetching.

---

**See the test suite and integration tests for more advanced usage and edge cases.**
