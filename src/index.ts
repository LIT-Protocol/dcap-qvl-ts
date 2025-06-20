// dcap-js: JavaScript/TypeScript port of https://github.com/Phala-Network/dcap-qvl
// MIT License

// Entry point for the dcap-js library

import { QuoteVerifier } from './quote-verifier';
import { CollateralFetcher } from './collateral-fetcher';
import { QuoteParser } from './quote-parser';
import {
  VerificationOptions,
  VerifiedReport,
  Quote,
  VerificationStatus,
  EnclaveReport,
  QuoteCollateralV3,
  QuoteVerificationError,
} from './quote-types';

/**
 * Main class for DCAP quote verification (public API)
 */
export class DcapVerifier {
  private verifier: QuoteVerifier;
  private collateralFetcher: CollateralFetcher;

  /**
   * Create a new DCAP verifier instance
   * @param options - Configuration options
   */
  constructor(options: VerificationOptions = {}) {
    this.collateralFetcher = new CollateralFetcher(options);
    this.verifier = new QuoteVerifier(this.collateralFetcher);
  }

  /**
   * Verify an SGX or TDX quote
   * @param quote - Raw quote bytes (Uint8Array or Buffer)
   * @param collateral - Optional: pre-fetched collateral (for advanced use)
   * @param now - Optional: current time (ms since epoch)
   * @returns A verification report with status and extracted data
   * @throws If quote is malformed, FMSPC cannot be extracted, or collateral fetching fails
   */
  async verifyQuote(
    quote: Uint8Array | Buffer,
    collateral?: QuoteCollateralV3,
    now?: number,
  ): Promise<VerifiedReport> {
    const quoteBytes = Buffer.isBuffer(quote) ? new Uint8Array(quote) : quote;
    try {
      if (collateral) {
        return await this.verifier.verify(quoteBytes, collateral, now);
      }
      // Parse the quote to extract FMSPC
      let parsedQuote: Quote;
      try {
        parsedQuote = QuoteParser.parse(quoteBytes);
      } catch (err) {
        throw new QuoteVerificationError(
          'DecodeError',
          `Malformed quote: ${(err as Error).message}`,
        );
      }
      let fmspc: string;
      try {
        const fmspcBytes = QuoteParser.extractFMSPC(parsedQuote);
        fmspc = Buffer.from(fmspcBytes).toString('hex');
        console.log('[DEBUG] Extracted FMSPC:', fmspc);
      } catch (err) {
        throw new QuoteVerificationError(
          'FieldMismatch',
          `Failed to extract FMSPC from quote: ${(err as Error).message}`,
        );
      }
      // Fetch TCB Info and QE Identity
      let tcbInfoRaw: string, qeIdentityRaw: string;
      try {
        if (this.collateralFetcher['options']?.isTdx) {
          console.log(
            '[DEBUG] Fetching TCB Info for TDX, URL:',
            this.collateralFetcher['baseUrl'] + '/tcb?fmspc=' + fmspc,
          );
        }
        tcbInfoRaw = await this.collateralFetcher.fetchTcbInfo(fmspc);
      } catch (err) {
        throw new QuoteVerificationError(
          'CertificateError',
          `Failed to fetch TCB Info for FMSPC ${fmspc}: ${(err as Error).message}`,
        );
      }
      try {
        qeIdentityRaw = await this.collateralFetcher.fetchQeIdentity();
      } catch (err) {
        throw new QuoteVerificationError(
          'CertificateError',
          `Failed to fetch QE Identity: ${(err as Error).message}`,
        );
      }
      // Parse and assemble QuoteCollateralV3
      let tcbInfoJson, tcbInfoIssuerChain;
      try {
        const result = await this.collateralFetcher.fetchTcbInfoWithIssuerChain(fmspc);
        tcbInfoJson = result.tcbInfoJson;
        tcbInfoIssuerChain = result.issuerChain;
        if (!tcbInfoIssuerChain || !tcbInfoIssuerChain.includes('-----BEGIN CERTIFICATE-----')) {
          console.error(
            '[ERROR] tcbInfoIssuerChain is missing or not PEM (from HTTP header):',
            tcbInfoIssuerChain,
          );
          throw new QuoteVerificationError(
            'CertificateError',
            'Missing or invalid tcbInfoIssuerChain (not PEM) in TCB Info HTTP header. Value: ' +
              tcbInfoIssuerChain.slice(0, 40) +
              '... Headers: ' +
              JSON.stringify(result.tcbInfoJson),
          );
        }
      } catch (err) {
        throw new QuoteVerificationError(
          'CertificateError',
          `Failed to fetch TCB Info for FMSPC ${fmspc}: ${(err as Error).message}`,
        );
      }
      // Extract required fields and signatures
      let qeIdentityJson;
      try {
        qeIdentityJson = JSON.parse(qeIdentityRaw);
      } catch (err) {
        throw new QuoteVerificationError(
          'DecodeError',
          `Failed to parse QE Identity JSON: ${(err as Error).message}`,
        );
      }
      try {
        const tcbInfo = tcbInfoJson.tcbInfo ? JSON.stringify(tcbInfoJson.tcbInfo) : tcbInfoRaw;
        const tcbInfoSignature = Buffer.from(tcbInfoJson.signature, 'hex');
        // Use tcbInfoIssuerChain from HTTP header (already validated above)
        const qeIdentity = qeIdentityJson.enclaveIdentity
          ? JSON.stringify(qeIdentityJson.enclaveIdentity)
          : qeIdentityRaw;
        const qeIdentitySignature = Buffer.from(qeIdentityJson.signature, 'hex');
        const qeIdentityIssuerChain =
          qeIdentityJson['qeIdentityIssuerChain'] ||
          qeIdentityJson['SGX-Enclave-Identity-Issuer-Chain'] ||
          '';
        const assembledCollateral: QuoteCollateralV3 = {
          tcbInfoIssuerChain,
          tcbInfo,
          tcbInfoSignature,
          qeIdentityIssuerChain,
          qeIdentity,
          qeIdentitySignature,
        };
        return await this.verifier.verify(quoteBytes, assembledCollateral, now);
      } catch (err) {
        throw new QuoteVerificationError(
          'CertificateError',
          `Failed to assemble collateral: ${(err as Error).message}`,
        );
      }
    } catch (err) {
      if (err instanceof QuoteVerificationError) throw err;
      throw new QuoteVerificationError(
        'UnknownError',
        `Quote verification failed: ${(err as Error).message}`,
      );
    }
  }

  /**
   * Extract information from a quote without verification
   * @param quote - Raw quote bytes (Uint8Array or Buffer)
   * @returns Parsed quote information
   * @throws If quote is malformed
   */
  parseQuote(quote: Uint8Array | Buffer): Quote {
    const quoteBytes = Buffer.isBuffer(quote) ? new Uint8Array(quote) : quote;
    return QuoteParser.parse(quoteBytes);
  }
}

export {
  VerificationOptions,
  VerifiedReport,
  Quote,
  VerificationStatus,
  EnclaveReport,
  QuoteVerifier,
};
