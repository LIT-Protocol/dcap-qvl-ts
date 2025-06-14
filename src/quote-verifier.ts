import { QuoteParser } from './quote-parser';
import { validateCertificateChain, verifyEcdsaSignature } from './crypto-utils';
import {
  parseCertificateChain,
  getIntelExtension,
  getFmspcFromIntelExtension,
  getCpuSvnFromIntelExtension,
  getPceSvnFromIntelExtension,
} from './binary-utils';
import { CollateralFetcher } from './collateral-fetcher';
import {
  VerifiedReport,
  QuoteCollateralV3,
  VerificationStatus,
  TcbInfo,
  TcbComponent,
} from './quote-types';
import forge from 'node-forge';

const allowedStatuses: VerificationStatus[] = [
  'UpToDate',
  'SWHardeningNeeded',
  'ConfigurationNeeded',
  'ConfigurationAndSWHardeningNeeded',
  'OutOfDate',
  'OutOfDateConfigurationNeeded',
  'Revoked',
  'Unknown',
];

export class QuoteVerifier {
  private collateralFetcher: CollateralFetcher;

  constructor(collateralFetcher: CollateralFetcher) {
    this.collateralFetcher = collateralFetcher;
  }

  async verify(quoteBytes: Uint8Array, collateral: QuoteCollateralV3): Promise<VerifiedReport> {
    // Parse the quote
    const quote = QuoteParser.parse(quoteBytes);

    // --- TCB Info Validation ---
    let tcbInfo: TcbInfo;
    try {
      tcbInfo = JSON.parse(collateral.tcbInfo);
    } catch {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // For TDX, check TCB info metadata
    const isTdx = quote.report.type === 'TD10' || quote.report.type === 'TD15';
    if (isTdx && (tcbInfo.id !== 'TDX' || tcbInfo.version < 3)) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Check TCB info expiration
    const now = Date.now();
    const nextUpdate = Date.parse(tcbInfo.nextUpdate);
    if (isNaN(nextUpdate) || now > nextUpdate) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Validate TCB info issuer chain
    const tcbCerts = parseCertificateChain(collateral.tcbInfoIssuerChain);
    try {
      validateCertificateChain(tcbCerts);
    } catch {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- TCB Info Signature Validation ---
    const tcbLeafCert = tcbCerts[0];
    const tcbInfoBytes = Buffer.from(collateral.tcbInfo, 'utf8');
    const tcbSig = collateral.tcbInfoSignature;
    const tcbLeafPubPem = forge.pki.publicKeyToPem(tcbLeafCert.publicKey);
    const validTcbSig = verifyEcdsaSignature({
      publicKey: tcbLeafPubPem,
      message: tcbInfoBytes,
      signature: tcbSig,
      isRaw: true,
    });
    if (!validTcbSig) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- PCK Certificate Chain Validation ---
    let pckPemChain: string;
    if (quote.authData.version === 3) {
      pckPemChain = Buffer.from(quote.authData.data.certificationData.body.data).toString('utf8');
    } else {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    const pckCerts = parseCertificateChain(pckPemChain);
    const trustedRoots = [tcbCerts[tcbCerts.length - 1]];
    try {
      validateCertificateChain(pckCerts, { trustedRoots });
    } catch {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- QE Report Signature Verification ---
    const pckLeafCert = pckCerts[0];
    const pckLeafPubPem = forge.pki.publicKeyToPem(pckLeafCert.publicKey);
    let qeReport: Uint8Array,
      qeReportSignature: Uint8Array,
      ecdsaAttestationKey: Uint8Array,
      qeAuthData: Uint8Array,
      ecdsaSignature: Uint8Array;
    if (quote.authData.version === 3) {
      qeReport = quote.authData.data.qeReport;
      qeReportSignature = quote.authData.data.qeReportSignature;
      ecdsaAttestationKey = quote.authData.data.ecdsaAttestationKey;
      qeAuthData = quote.authData.data.qeAuthData.data;
      ecdsaSignature = quote.authData.data.ecdsaSignature;
    } else {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    const validQeReportSig = verifyEcdsaSignature({
      publicKey: pckLeafPubPem,
      message: qeReport,
      signature: qeReportSignature,
      isRaw: true,
    });
    if (!validQeReportSig) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- QE Report Hash Check ---
    const hashInput = new Uint8Array(ecdsaAttestationKey.length + qeAuthData.length);
    hashInput.set(ecdsaAttestationKey, 0);
    hashInput.set(qeAuthData, ecdsaAttestationKey.length);
    const qeHash = forge.md.sha256.create();
    qeHash.update(Buffer.from(hashInput).toString('binary'));
    const qeHashBytes = new Uint8Array(Buffer.from(qeHash.digest().getBytes(), 'binary'));
    const reportData = qeReport.slice(320, 384); // 64 bytes
    const reportDataHash = reportData.slice(0, 32);
    if (!qeHashBytes.every((b, i) => b === reportDataHash[i])) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- Quote Signature Verification (using attestation key) ---
    const signedQuoteLen = quoteBytes.length - 64;
    const signedQuote = quoteBytes.slice(0, signedQuoteLen);
    const validQuoteSig = verifyEcdsaSignature({
      publicKey: ecdsaAttestationKey,
      message: signedQuote,
      signature: ecdsaSignature,
      isRaw: true,
    });
    if (!validQuoteSig) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- FMSPC, CPU SVN, PCE SVN Extraction and TCB Status/Advisory Determination ---
    // Extract Intel SGX extension from PCK leaf cert
    const intelExt = getIntelExtension(pckLeafCert);
    if (!intelExt) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Extract FMSPC, CPU SVN, PCE SVN from the extension
    const fmspc = getFmspcFromIntelExtension(intelExt);
    const cpuSvn = getCpuSvnFromIntelExtension(intelExt);
    const pceSvn = getPceSvnFromIntelExtension(intelExt);
    if (!fmspc || !cpuSvn || !pceSvn) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Compare FMSPC to tcbInfo.fmspc (hex string)
    const fmspcHex = Buffer.from(fmspc).toString('hex');
    const tcbFmspcHex = tcbInfo.fmspc?.toLowerCase();
    if (!tcbFmspcHex || fmspcHex !== tcbFmspcHex) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Extract CPU SVN and PCE SVN from the quote
    let quoteCpuSvn: Uint8Array | undefined;
    let quotePceSvn: Uint8Array | undefined;
    if (quote.report.type === 'SgxEnclave') {
      quoteCpuSvn = quote.report.report.cpuSvn;
      quotePceSvn = new Uint8Array(2);
      const pceSvnVal = quote.header.pceSvn;
      quotePceSvn[0] = pceSvnVal & 0xff;
      quotePceSvn[1] = (pceSvnVal >> 8) & 0xff;
    } else if (quote.report.type === 'TD10') {
      quoteCpuSvn = quote.report.report.teeTcbSvn;
      // TODO: Extract PCE SVN for TDX if needed
    }
    if (!quoteCpuSvn || !quotePceSvn) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Find matching TCB level
    let tcbStatus: VerificationStatus = 'Unknown';
    let advisoryIds: string[] = [];
    if (tcbInfo.tcbLevels && Array.isArray(tcbInfo.tcbLevels)) {
      for (const tcbLevel of tcbInfo.tcbLevels) {
        // Compare PCE SVN
        const tcbPceSvn = tcbLevel.tcb?.pceSvn;
        if (tcbPceSvn === undefined) continue;
        if (quotePceSvn.length === 2) {
          const tcbPceSvnVal = (quotePceSvn[1] << 8) | quotePceSvn[0];
          if (tcbPceSvnVal < tcbPceSvn) continue;
        }
        // TDX: Compare teeTcbSvn to tdxComponents
        if (
          isTdx &&
          Array.isArray(tcbLevel.tcb.tdxComponents) &&
          tcbLevel.tcb.tdxComponents.length === 16
        ) {
          const teeTcbSvn =
            quote.report.type === 'TD10'
              ? quote.report.report.teeTcbSvn
              : quote.report.type === 'TD15'
                ? quote.report.report.base.teeTcbSvn
                : undefined;
          if (!teeTcbSvn || teeTcbSvn.length !== 16) continue;
          let tdxOk = true;
          for (let i = 0; i < 16; i++) {
            if (teeTcbSvn[i] < tcbLevel.tcb.tdxComponents[i].svn) {
              tdxOk = false;
              break;
            }
          }
          if (!tdxOk) continue;
        } else if (!isTdx) {
          // SGX: Compare CPU SVN to sgxComponents
          const tcbCpuSvn = tcbLevel.tcb?.sgxComponents?.map((c: TcbComponent) => c.svn);
          if (!Array.isArray(tcbCpuSvn) || tcbCpuSvn.length !== 16) continue;
          let cpuSvnOk = true;
          for (let i = 0; i < 16; i++) {
            if (quoteCpuSvn[i] < tcbCpuSvn[i]) {
              cpuSvnOk = false;
              break;
            }
          }
          if (!cpuSvnOk) continue;
        }
        // If all checks pass, use this TCB level
        const status = tcbLevel.tcbStatus || 'Unknown';
        if (allowedStatuses.includes(status as VerificationStatus)) {
          tcbStatus = status as VerificationStatus;
        } else {
          tcbStatus = 'Unknown';
        }
        if (Array.isArray(tcbLevel.advisoryIDs)) {
          advisoryIds = tcbLevel.advisoryIDs;
        }
        break;
      }
    }
    // --- Debug/Production Mode Check ---
    let debugMode = false;
    if (quote.report.type === 'SgxEnclave') {
      // SGX: attributes[0] & 0x02 != 0 means debug mode
      const attrs = quote.report.report.attributes;
      if (attrs && attrs[0] !== undefined && (attrs[0] & 0x02) !== 0) {
        debugMode = true;
      }
    } else if (quote.report.type === 'TD10') {
      // TDX TD10: tdAttributes[0] != 0 means debug mode
      const tdAttrs = quote.report.report.tdAttributes;
      if (tdAttrs && tdAttrs[0] !== undefined && tdAttrs[0] !== 0) {
        debugMode = true;
      }
    } else if (quote.report.type === 'TD15') {
      // TDX TD15: mrServiceTd != [0u8; 48] means debug mode (see Rust)
      const mrServiceTd = quote.report.report.mrServiceTd;
      if (mrServiceTd && Array.isArray(mrServiceTd) && mrServiceTd.some((b: number) => b !== 0)) {
        debugMode = true;
      }
    }
    if (debugMode) {
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    return {
      status: tcbStatus,
      advisoryIds,
      report: quote.report,
    };
  }
}
