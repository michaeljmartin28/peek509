import * as forge from 'node-forge';

export interface DecodedCert {
  subject: { name: string; value: string }[];
  issuer: { name: string; value: string }[];
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  signature: string;
  publicKey: forge.pki.PublicKey;
  fingerprint: string;
  extensions?: {
    name: string;
    value: string;
    critical?: boolean;
  }[];
}
