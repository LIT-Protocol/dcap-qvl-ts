import { QuoteParser } from './quote-parser';
import { verifyEcdsaSignature } from './crypto-utils';
import { parseCertificateChain } from './binary-utils';
import { CollateralFetcher } from './collateral-fetcher';
import { VerifiedReport, QuoteCollateralV3, VerificationStatus, TcbInfo } from './quote-types';
import { sha256 } from '@noble/hashes/sha256';

declare module './quote-types' {
  interface TcbInfo {
    tdxModuleIdentities?: unknown[]; // For Intel TDX collateral compatibility
  }
}

export class QuoteVerifier {
  private collateralFetcher: CollateralFetcher;

  constructor(collateralFetcher: CollateralFetcher) {
    this.collateralFetcher = collateralFetcher;
  }

  async verify(quoteBytes: Uint8Array, collateral: QuoteCollateralV3): Promise<VerifiedReport> {
    console.log('[TDX DEBUG] Entered verify function');
    // Parse the quote
    const quote = QuoteParser.parse(quoteBytes);

    // --- TCB Info Validation ---
    let tcbInfo: TcbInfo;
    try {
      tcbInfo = JSON.parse(collateral.tcbInfo);
      console.log('[TDX DEBUG] Parsed tcbInfo:', tcbInfo);
      console.log('[TDX DEBUG] tcbInfo keys:', Object.keys(tcbInfo));
      console.log('[TDX DEBUG] typeof tcbInfo.tcbLevels:', typeof tcbInfo.tcbLevels);
      console.log(
        '[TDX DEBUG] Array.isArray(tcbInfo.tcbLevels):',
        Array.isArray(tcbInfo.tcbLevels),
      );
      console.log(
        '[TDX DEBUG] tcbInfo.tcbLevels value:',
        JSON.stringify(tcbInfo.tcbLevels, null, 2).slice(0, 500),
      );
    } catch {
      console.log('[TDX DEBUG] Early return: failed to parse tcbInfo');
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    console.log('[TDX DEBUG] After parsing tcbInfo');
    // For TDX, check TCB info metadata
    const isTdx = quote.report.type === 'TD10' || quote.report.type === 'TD15';
    console.log('[TDX DEBUG] isTdx:', isTdx);
    if (isTdx && (tcbInfo.id !== 'TDX' || tcbInfo.version < 3)) {
      console.log(
        '[TDX DEBUG] Early return: TDX but tcbInfo.id/version mismatch',
        tcbInfo.id,
        tcbInfo.version,
      );
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    console.log('[TDX DEBUG] After TDX id/version check');
    // Check TCB info expiration
    const now = Date.now();
    if (tcbInfo.nextUpdate && now > new Date(tcbInfo.nextUpdate).getTime()) {
      console.log(
        '[TDX DEBUG] Early return: tcbInfo.nextUpdate expired',
        tcbInfo.nextUpdate,
        'now:',
        new Date(now).toISOString(),
      );
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    if (tcbInfo.issueDate && now < new Date(tcbInfo.issueDate).getTime()) {
      console.log(
        '[TDX DEBUG] Early return: tcbInfo.issueDate in future',
        tcbInfo.issueDate,
        'now:',
        new Date(now).toISOString(),
      );
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    console.log('[TDX DEBUG] After tcbLevels check');
    // Validate TCB info issuer chain
    const tcbCerts = parseCertificateChain(collateral.tcbInfoIssuerChain);
    // --- TCB Info Signature Validation ---
    const tcbLeafCert = tcbCerts[0];
    const tcbInfoBytes = Buffer.from(collateral.tcbInfo, 'utf8');
    const tcbSig = collateral.tcbInfoSignature;
    // Debug output for signature verification
    console.log(
      '[TDX DEBUG] tcbLeafCert.publicKey (hex):',
      Buffer.from(tcbLeafCert.publicKey).toString('hex'),
    );
    console.log('[TDX DEBUG] tcbInfoBytes (hex):', tcbInfoBytes.toString('hex'));
    console.log('[TDX DEBUG] tcbInfoBytes (utf8):', tcbInfoBytes.toString('utf8').slice(0, 200));
    console.log('[TDX DEBUG] tcbSig (hex):', Buffer.from(tcbSig).toString('hex'));
    const validTcbSig = verifyEcdsaSignature({
      publicKey: tcbLeafCert.publicKey,
      message: tcbInfoBytes,
      signature: tcbSig,
      isRaw: true,
    });
    if (!validTcbSig) {
      console.log('[TDX DEBUG] Early return: invalid tcbInfo signature');
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- PCK Certificate Chain Validation ---
    let pckPemChain: string;
    let qeReport: Uint8Array,
      qeReportSignature: Uint8Array,
      ecdsaAttestationKey: Uint8Array,
      qeAuthData: Uint8Array,
      ecdsaSignature: Uint8Array;
    if (quote.authData.version === 3) {
      pckPemChain = Buffer.from(quote.authData.data.certificationData.body.data).toString('utf8');
      qeReport = quote.authData.data.qeReport;
      qeReportSignature = quote.authData.data.qeReportSignature;
      ecdsaAttestationKey = quote.authData.data.ecdsaAttestationKey;
      qeAuthData = quote.authData.data.qeAuthData.data;
      ecdsaSignature = quote.authData.data.ecdsaSignature;
    } else if (quote.authData.version === 4) {
      // For TDX v4, use nested QEReportCertificationData
      pckPemChain = Buffer.from(
        quote.authData.data.qeReportData.certificationData.body.data,
      ).toString('utf8');
      qeReport = quote.authData.data.qeReportData.qeReport;
      qeReportSignature = quote.authData.data.qeReportData.qeReportSignature;
      ecdsaAttestationKey = quote.authData.data.ecdsaAttestationKey;
      qeAuthData = quote.authData.data.qeReportData.qeAuthData.data;
      ecdsaSignature = quote.authData.data.ecdsaSignature;
    } else {
      console.log('[TDX DEBUG] Early return: invalid authData version');
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    const pckCerts = parseCertificateChain(pckPemChain);
    // --- QE Report Signature Verification ---
    const pckLeafCert = pckCerts[0];
    const validQeReportSig = verifyEcdsaSignature({
      publicKey: pckLeafCert.publicKey,
      message: qeReport,
      signature: qeReportSignature,
      isRaw: true,
    });
    if (!validQeReportSig) {
      console.log('[TDX DEBUG] Early return: invalid qeReport signature');
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
    const qeHashBytes = sha256(hashInput);
    const reportData = qeReport.slice(320, 384); // 64 bytes
    const reportDataHash = reportData.slice(0, 32);
    if (!qeHashBytes.every((b, i) => b === reportDataHash[i])) {
      console.log('[TDX DEBUG] Early return: qeHashBytes mismatch');
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
      console.log('[TDX DEBUG] Early return: invalid quote signature');
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // --- FMSPC, CPU SVN, PCE SVN Extraction and TCB Status/Advisory Determination ---
    // TODO: Implement extension extraction for FMSPC, CPU SVN, PCE SVN if needed
    // Extract Intel SGX extension from PCK leaf cert
    // Extract FMSPC, CPU SVN, PCE SVN from the extension
    // Compare FMSPC to tcbInfo.fmspc (hex string)
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
      // For TDX, PCE SVN is not used in TCB comparison (see Rust reference)
      quotePceSvn = new Uint8Array([0, 0]);
    }
    if (!quoteCpuSvn || !quotePceSvn) {
      console.log('[TDX DEBUG] Early return: quoteCpuSvn or quotePceSvn is undefined');
      return {
        status: 'Unknown',
        advisoryIds: [],
        report: quote.report,
      };
    }
    // Find matching TCB level
    console.log('[TDX DEBUG] About to find matching TCB level');
    let tcbStatus: VerificationStatus = 'Unknown';
    let advisoryIds: string[] = [];
    let tcbLevelsToCheck: unknown[] = [];
    if (Array.isArray(tcbInfo.tcbLevels) && tcbInfo.tcbLevels.length > 0) {
      tcbLevelsToCheck = tcbInfo.tcbLevels;
      console.log('[TDX DEBUG] tcbLevelsToCheck length:', tcbLevelsToCheck.length);
      for (let idx = 0; idx < tcbLevelsToCheck.length; idx++) {
        try {
          const tcbLevelRaw = tcbLevelsToCheck[idx];
          const tcbLevelObj = tcbLevelRaw as Record<string, unknown>;
          console.log(`[TDX DEBUG] tcbLevel[${idx}] keys:`, Object.keys(tcbLevelObj));
          const tcbLevel = tcbLevelRaw as {
            tcb: unknown;
            tcbStatus?: string;
            advisoryIDs?: string[];
          };
          const tcbObj = tcbLevel.tcb as Record<string, unknown>;
          const tdxComponents = Array.isArray(tcbObj['tdxtcbcomponents'])
            ? (tcbObj['tdxtcbcomponents'] as { svn: number }[])
            : undefined;
          if (
            isTdx &&
            tdxComponents &&
            Array.isArray(tdxComponents) &&
            tdxComponents.length === 16
          ) {
            const teeTcbSvn =
              quote.report.type === 'TD10'
                ? quote.report.report.teeTcbSvn
                : quote.report.type === 'TD15'
                  ? quote.report.report.base.teeTcbSvn
                  : undefined;
            if (!teeTcbSvn || teeTcbSvn.length !== 16) continue;
            let match = true;
            for (let i = 0; i < 16; i++) {
              if (teeTcbSvn[i] < tdxComponents[i].svn) {
                match = false;
                break;
              }
            }
            if (match) {
              tcbStatus = (tcbLevel.tcbStatus as VerificationStatus) || 'Unknown';
              advisoryIds = tcbLevel.advisoryIDs || [];
              break;
            }
          }
        } catch (err) {
          console.log('[TDX DEBUG] Exception in tcbLevel loop:', err);
        }
      }
    } else if (isTdx && tcbInfo.tdxModuleIdentities && Array.isArray(tcbInfo.tdxModuleIdentities)) {
      // Only fallback to tdxModuleIdentities if tcbLevels is missing/empty
      tcbLevelsToCheck = (tcbInfo.tdxModuleIdentities as unknown[]).flatMap((id) =>
        Array.isArray((id as Record<string, unknown>)['tcbLevels'])
          ? ((id as Record<string, unknown>)['tcbLevels'] as unknown[])
          : [],
      );
      console.log('[TDX DEBUG] Using tdxModuleIdentities for TDX TCB comparison.');
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
    if (tcbStatus === 'Unknown') {
      console.log('[TDX DEBUG] Early return: tcbStatus is Unknown at end');
      return {
        status: tcbStatus,
        advisoryIds,
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
