import * as forge from 'node-forge';
import { DecodedCert } from './types';

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

function pad(label: string, width = 32): string {
  return label.padEnd(width, ' ');
}

function getSignatureHex(cert: forge.pki.Certificate): string {
  const signatureBytes = cert.signature;
  const hex = forge.util.bytesToHex(signatureBytes);
  return hex.match(/.{2}/g)?.join(':') ?? hex;
}

function formatSubjectOrIssuer(attrs: { name: string; value: string }[]): string {
  let output = '';

  for (const attr of attrs) {
    switch (attr.name) {
      case 'commonName':
        output += `${pad('    Common Name (CN):')}${attr.value}\n`;
        break;
      case 'organizationName':
        output += `${pad('    Organization (O):')}${attr.value}\n`;
        break;
      case 'organizationalUnitName':
        output += `${pad('    Organizational Unit (OU):')}${attr.value}\n`;
        break;
      case 'countryName':
        output += `${pad('    Country (C):')}${attr.value}\n`;
        break;
      case 'localityName':
        output += `${pad('    Locality (L):')}${attr.value}\n`;
        break;
      case 'stateOrProvinceName':
        output += `${pad('    State (S):')}${attr.value}\n`;
        break;
      case 'emailAddress':
        output += `${pad('    Email:')}${attr.value}\n`;
        break;
      default:
        output += `${pad('    ' + attr.name)}: ${attr.value}\n`;
        break;
    }
  }
  output = output.replace(/, $/, '');
  return output;
}

function getSha256Fingerprint(cert: forge.pki.Certificate): string {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(derBytes);
  const digest = md.digest().toHex();
  return digest.match(/.{2}/g)?.join('') ?? digest;
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
  output += formatSubjectOrIssuer(decoded.subject) + '\n';
  output += 'Issuer:\n';
  output += formatSubjectOrIssuer(decoded.issuer) + '\n';
  output += `Serial Number: ${decoded.serialNumber}\n`;
  output += `Validity:\n\tNot Before: ${decoded.notBefore}\n\tNot After: ${decoded.notAfter}\n`;
  output += `Fingerprint (SHA-256): ${decoded.fingerprint}\n`;
  output += `Signature: ${decoded.signature.slice(0, 11)} ... ${decoded.signature.slice(-11)}\n`;
  output += `Public Key:\n`;
  for (const [key, value] of Object.entries(pubFormatted)) {
    output += `\t${key}: ${value}\n`;
  }
  if (decoded.extensions) {
    output += 'Extensions:\n Coming soon...\n';
  }
  return output;
}
