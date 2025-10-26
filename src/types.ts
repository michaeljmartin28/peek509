import * as forge from 'node-forge';

export interface DecodedCert {
  subject: { name: string; value: string }[];
  issuer: { name: string; value: string }[];
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  signature: string;
  publicKey: forge.pki.PublicKey & {
    n?: forge.jsbn.BigInteger;
    e?: forge.jsbn.BigInteger;
    curve?: { name: string };
  };
  fingerprint: string;
  extensions?: {
    name: string;
    value: string;
    critical?: boolean;
  }[];
}
