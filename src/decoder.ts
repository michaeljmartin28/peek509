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
      decodedPem: pem,
    };
    return decoded;
  } catch (error) {
    console.error('Failed to decode certificate:', error);
    return null;
  }
}

/**
 * Adds padding to a string to print out in a table format.
 * @param label The string to pad.
 * @param width The total width of the returned string with padding.
 * @returns The padded string.
 */
function pad(label: string, width = 32): string {
  return label.padEnd(width, ' ');
}

/**
 * Converts the certificate signature into a hex string
 * @param cert The Node-Forge PKI certificate.
 * @returns The signature as a hex string.
 */
function getSignatureHex(cert: forge.pki.Certificate): string {
  const signatureBytes = cert.signature;
  const hex = forge.util.bytesToHex(signatureBytes);
  return hex.match(/.{2}/g)?.join(':') ?? hex;
}

/**
 * Formats a string to view the subject or issuer section of an x509 certificate.
 * @param attrs The attributes (name, value) of a certificates subject or issuer section.
 * @returns A formatted string that prints attributes.
 */
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

/**
 * Computes the SHA256 fingerprint of an x509 certificate.
 * @param cert the Node-Forge PKI certificate to hash.
 * @returns The hex-string hash of the certificate.
 */
function getSha256Fingerprint(cert: forge.pki.Certificate): string {
  const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(derBytes);
  const digest = md.digest().toHex();
  return digest.match(/.{2}/g)?.join('') ?? digest;
}

/**
 * Formats a DecodedCert into a single string to print in a text format.
 * @param decoded The DecocdedCert object to format.
 * @returns A single multi-line string to prettyprint the DecodedCert.
 */
export function formatCertificate(decoded: DecodedCert): string {
  let pubFormatted = {};

  if (decoded.publicKey.n && decoded.publicKey.e) {
    // RSA Key
    pubFormatted = {
      Algorithm: 'RSA',
      KeySize: decoded.publicKey.n.bitLength(),
      Exponent: decoded.publicKey.e.toString(),
    };
  } else if (decoded.publicKey.curve) {
    // ECDSA Key
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
    output += 'Extensions:\n';
    for (const ext of decoded.extensions) {
      const parsedExt = parseExtension(ext);
      console.log(parsedExt);
      output += `\t${parsedExt.name} (Critical: ${parsedExt.critical})\n`;
      output += `\t\tValue: ${parsedExt.value}\n`;
    }
  }
  output += '\n\n' + '~'.repeat(50) + '\n';
  output += '\nPEM Content:\n\n';
  output += decoded.decodedPem || '';
  return output;
}

/**
 * Parses an extexsion and, if supported, decodes its ASN.1 value into readable text.
 * @param ext The extension (name, value, critical?)
 * @returns
 */
function parseExtension(ext: { name: string; value: string; critical?: boolean }): any {
  switch (ext.name) {
    case 'basicConstraints':
      const rawValue = ext.value;

      const asn1Object = forge.asn1.fromDer(rawValue);
      console.log('Decoded ASN.1 structure:', JSON.stringify(asn1Object, null, 2));

      return {
        name: 'Basic Constraints',
        critical: ext.critical || false,
        value: 'Unknown - Full extension parsing coming in a future update.',
      };
    case 'keyUsage':
      return {
        name: 'Key Usage',
        critical: ext.critical || false,
        value: 'Unknown - Full extension parsing coming in a future update.',
      };
    case 'subjectKeyIdentifier':
      return {
        name: 'Subject Key Identifier',
        critical: ext.critical || false,
        value: 'Unknown - Full extension parsing coming in a future update.',
      };
    case 'authorityKeyIdentifier':
      return {
        name: 'Authority Key Identifier',
        critical: ext.critical || false,
        value: 'Unknown - Full extension parsing coming in a future update.',
      };
    case 'subjectAltName':
      return {
        name: 'Subject Alternative Name',
        critical: ext.critical || false,
        value: 'Unknown - Full extension parsing coming in a future update.',
      };
    default:
      return {
        name: ext.name,
        critical: ext.critical || false,
        value: ext.value || ext.toString(),
      };
  }
}
