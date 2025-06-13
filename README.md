# dcap-js

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A JavaScript/TypeScript port of the [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) Rust project.

## Overview

This library implements quote verification logic for DCAP (Data Center Attestation Primitives) in pure JavaScript/TypeScript. It is inspired by and ports the functionality of the original Rust crate, supporting SGX and TDX quotes.

## Features

- Verify SGX and TDX quotes
- Get collateral from PCCS
- Extract information from quotes

## Installation

```bash
npm install dcap-js
```

## Usage

```typescript
import { verifyQuote, getCollateral } from 'dcap-js';

// Example usage
const quote = ...; // Load your quote
const collateral = await getCollateral(pccsUrl, quote);
const result = verifyQuote(quote, collateral);
console.log(result);
```

## Examples

See the `examples/` directory for more usage examples.

## Contributing

Contributions are welcome! Please open issues or pull requests. See the [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Reference

This is a JavaScript/TypeScript port of the [Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl) Rust project.
