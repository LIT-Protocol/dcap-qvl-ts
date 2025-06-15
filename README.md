# dcap-js

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**[📖 API Documentation](https://LIT-Protocol.github.io/dcap-qvl-ts/)**

A JavaScript/TypeScript port of the [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) Rust project.

## Overview

This library implements quote verification logic for DCAP (Data Center Attestation Primitives) in pure JavaScript/TypeScript. It is a direct port of the original Rust crate, supporting SGX and TDX quotes.

## Features

- Verify SGX and TDX quotes
- Get collateral from PCCS
- Extract information from quotes

## Installation

```bash
npm install @lit-protocol/dcap-qvl-ts
```

## Usage Examples

This guide demonstrates how to use the dcap-js public API for Intel SGX/TDX quote verification and parsing.

### 1. Basic Quote Verification (with Provided Collateral)

**CommonJS:**

```js
const { DcapVerifier } = require('@lit-protocol/dcap-qvl-ts');
const fs = require('fs');
const path = require('path');

const quotePath = path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote');
const collateralPath = path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote_collateral.json');
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
(async () => {
  const result = await verifier.verifyQuote(quoteBytes, collateral);
  console.log('Verification result:', result);
})();
```

**ESM:**

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

### 2. Automatic Collateral Fetching

```js
const { DcapVerifier } = require('@lit-protocol/dcap-qvl-ts');
const fs = require('fs');
const path = require('path');

const quotePath = path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote');
const quoteBytes = fs.readFileSync(quotePath);

const verifier = new DcapVerifier({
  // Optionally set PCCS URL, timeouts, etc.
  // pccsUrl: 'https://localhost:8081/sgx/certification/v4',
});
(async () => {
  try {
    const result = await verifier.verifyQuote(quoteBytes);
    console.log('Verification result:', result);
  } catch (err) {
    console.error('Verification failed:', err);
  }
})();
```

---

### 3. Custom Verification Options

```js
const { DcapVerifier } = require('@lit-protocol/dcap-qvl-ts');
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

### 4. Quote Parsing Without Verification

```js
const { DcapVerifier } = require('@lit-protocol/dcap-qvl-ts');
const fs = require('fs');
const path = require('path');

const quotePath = path.join(__dirname, '../dcap-qvl-rust/sample/sgx_quote');
const quoteBytes = fs.readFileSync(quotePath);

const verifier = new DcapVerifier();
const parsed = verifier.parseQuote(quoteBytes);
console.log('Parsed quote:', parsed);
```

---

### 5. Error Handling Example

```js
const { DcapVerifier } = require('@lit-protocol/dcap-qvl-ts');
const verifier = new DcapVerifier();
(async () => {
  try {
    // Intentionally pass a malformed quote
    await verifier.verifyQuote(Buffer.from([1, 2, 3]));
  } catch (err) {
    console.error('Expected error:', err.message);
  }
})();
```

---

### 6. Working with Different Quote Formats

- The API supports both SGX and TDX quotes (V3, V4, V5). Use the same methods as above.
- For TDX, set `isTdx: true` in options if needed for collateral fetching.

---

**See the test suite and integration tests for more advanced usage and edge cases.**

## Contributing

Contributions are welcome! Please open issues or pull requests. See the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Reference

This is a JavaScript/TypeScript port of the [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) Rust project.
