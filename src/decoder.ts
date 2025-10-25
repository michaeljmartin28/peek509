import * as forge from 'node-forge';
import { DecodedCert } from './types';
import { decode } from 'punycode';

/**
 * Decodes a PEM-encoded X.509 certificate using node-forge.
 * @param pem
 * @returns
 */
export function decodeCertificate(pem: string): DecodedCert | null {
  try {
    const cert = forge.pki.certificateFromPem(pem);
    const decoded: DecodedCert = {
      subject: cert.subject.attributes.map(attr => ({
        name: attr.name || attr.type || attr.shortName || 'unknown',
        value: String(attr.value),
      })),
      issuer: cert.issuer.attributes.map(attr => ({
        name: attr.name || attr.type || attr.shortName || 'unknown',
        value: String(attr.value),
      })),
      serialNumber: cert.serialNumber,
      notBefore: cert.validity.notBefore,
      notAfter: cert.validity.notAfter,
      signature: getSignatureHex(cert),
      publicKey: cert.publicKey,
      fingerprint: getSha256Fingerprint(cert),
      extensions: cert.extensions?.map(ext => ({
        name: ext.name,
        value: ext.value,
        critical: ext.critical,
      })),
    };
    return decoded;
  } catch (error) {
    console.error('Failed to decode certificate:', error);
    return null;
  }
}

function getSignatureHex(cert: forge.pki.Certificate): string {
  const signatureBytes = cert.signature;
  const hex = forge.util.bytesToHex(signatureBytes);
  return hex.match(/.{2}/g)?.join(':') ?? hex;
}

function getSha256Fingerprint(cert: forge.pki.Certificate): string {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(derBytes);
  const digest = md.digest().toHex();
  return digest.match(/.{2}/g)?.join('') ?? digest; // Format as colon-separated hex
}

export function formatCertificate(decoded: DecodedCert): string {
  let pubFormatted = {};

  if (decoded.publicKey.n && decoded.publicKey.e) {
    pubFormatted = {
      Algorithm: 'RSA',
      KeySize: decoded.publicKey.n.bitLength(),
      Exponent: decoded.publicKey.e.toString(),
    };
  } else if (decoded.publicKey.curve) {
    pubFormatted = {
      Algorithm: 'ECDSA',
      Curve: decoded.publicKey.curve.name,
    };
  } else {
    pubFormatted = {
      Algorithm: 'Unknown',
    };
  }

  let output = '';
  output += 'Subject:\n';
  decoded.subject.forEach(attr => {
    output += `  ${attr.name}: ${attr.value}\n`;
  });
  output += 'Issuer:\n';
  decoded.issuer.forEach(attr => {
    output += `  ${attr.name}: ${attr.value}\n`;
  });
  output += `Serial Number: ${decoded.serialNumber}\n`;
  output += `Validity:\n  Not Before: ${decoded.notBefore}\n  Not After: ${decoded.notAfter}\n`;
  output += `Fingerprint (SHA-256): ${decoded.fingerprint}\n`;
  output += `Signature: ${decoded.signature.slice(0, 11)} ... ${decoded.signature.slice(-11)}\n`;
  output += `Public Key:\n`;
  for (const [key, value] of Object.entries(pubFormatted)) {
    output += `  ${key}: ${value}\n`;
  }
  if (decoded.extensions) {
    output += 'Extensions:\n Coming soon...\n';
  }
  return output;
}
