import type { CheckStatus } from "../types.js";

/** Role of a certificate in the chain */
export type CertRole = "leaf" | "intermediate" | "root";

/** Information about a certificate in the chain */
export interface ChainCertInfo {
  subject: string;       // CN
  issuer: string;        // O or CN of issuer
  validFrom: string;     // ISO date
  validTo: string;       // ISO date
  isSelfSigned: boolean;
  role: CertRole;
}

/** Issue found in the certificate chain */
export interface ChainIssue {
  severity: CheckStatus; // "fail" | "warn"
  message: string;
}

/** Information about a single SCT */
export interface SctInfo {
  version: number;
  logId: string;          // hex SHA-256
  timestamp: number;      // Unix ms
  logName: string | null; // name from registry or null
  operator: string | null;
}

/** Result of CT policy check */
export interface CtPolicyResult {
  scts: SctInfo[];
  chromeStatus: CheckStatus;
  appleStatus: CheckStatus;
  findings: CtPolicyFinding[];
}

/** CT policy finding */
export interface CtPolicyFinding {
  severity: CheckStatus;
  message: string;
}
