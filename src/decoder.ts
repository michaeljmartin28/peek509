import { DecodedCert, ParsedExtension, oidMap, extensionOidMap } from './types';
import { parseBasicConstraints } from './extensionParser/parsers/basicConstraints';
import { parseKeyUsage } from './extensionParser/parsers/keyUsage';
import { parseSubjectAltName } from './extensionParser/parsers/subjectAltName';
import { createHash } from 'crypto';
import { fromBER } from 'asn1js';
import { Certificate } from 'pkijs';
import { bufferToHexCodes } from 'pvutils';
import { parseExtendedKeyUsage } from './extensionParser/parsers/extendedKeyUsage';
import { parseSubjectKeyIdentifier } from './extensionParser/parsers/subjectKeyIdentifier';
import { parseAuthorityKeyIdentifier } from './extensionParser/parsers/authorityKeyIdentifier';

/**
 * Decodes a PEM-encoded X.509 certificate.
 * @param pem
 * @returns
 */
export async function decodeCertificate(pem: string): Promise<DecodedCert> {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const asn1 = fromBER(der.buffer);
  if (asn1.offset === -1) throw new Error('Failed to decode ASN.1');

  const cert = new Certificate({ schema: asn1.result });

  const subject = cert.subject.typesAndValues.map(tv => ({
    name: tv.type,
    value: tv.value.valueBlock.value,
  }));

  const issuer = cert.issuer.typesAndValues.map(tv => ({
    name: tv.type,
    value: tv.value.valueBlock.value,
  }));

  const serialNumber = cert.serialNumber.valueBlock.toString();
  const notBefore = cert.notBefore.value;
  const notAfter = cert.notAfter.value;
  const signature = cert.signatureAlgorithm.algorithmId;

  const algorithmOID = cert.subjectPublicKeyInfo.algorithm.algorithmId;
  const publicKey: DecodedCert['publicKey'] = {
    type: 'Unknown',
    algorithmOID,
  };

  const spki = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;

  if (algorithmOID === '1.2.840.113549.1.1.1') {
    // RSA
    const rsaAsn1 = fromBER(spki);
    const rsaSeq = (rsaAsn1.result.valueBlock as any).value;

    const modulus = bufferToHexCodes(rsaSeq[0].valueBlock.valueHex);
    const exponent = parseInt(rsaSeq[1].valueBlock.valueDec.toString(), 10);

    publicKey.type = 'RSA';
    publicKey.rsa = { modulus, exponent };
  } else if (algorithmOID === '1.2.840.10045.2.1') {
    // ECDSA
    const curveOID = cert.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString();
    const publicKeyHex = bufferToHexCodes(spki);

    publicKey.type = 'ECDSA';
    publicKey.ecdsa = {
      curveOID,
      publicKeyHex,
    };
  }

  // SHA-256 fingerprint
  const digest = await createHash('sha256').update(Buffer.from(der)).digest();
  const fingerprint = bufferToHexCodes(digest.buffer);

  const extensions = cert.extensions?.map(ext => {
    const binaryValue = String.fromCharCode(...new Uint8Array(ext.extnValue.valueBlock.valueHex));
    const name = extensionOidMap[ext.extnID] ?? ext.extnID;

    return {
      name,
      binaryValue,
      critical: ext.critical,
    };
  });

  return {
    subject,
    issuer,
    serialNumber,
    notBefore,
    notAfter,
    signature,
    publicKey,
    fingerprint,
    extensions,
    decodedPem: pem,
  };
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
 * Formats a string to view the subject or issuer section of an x509 certificate.
 * @param attrs The attributes (name, value) of a certificates subject or issuer section.
 * @returns A formatted string that prints attributes.
 */
function formatSubjectOrIssuer(attrs: { name: string; value: string }[]): string {
  let output = '';

  for (const attr of attrs) {
    const label = oidMap[attr.name] ?? `OID ${attr.name}`;
    output += `${pad(`    ${label}:`)}${attr.value}\n`;
  }

  return output.replace(/, $/, '');
}

/**
 * Formats a DecodedCert into a single string to print in a text format.
 * @param decoded The DecocdedCert object to format.
 * @returns A single multi-line string to prettyprint the DecodedCert.
 */
export function formatCertificate(decoded: DecodedCert): string {
  let pubFormatted = {};

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
  if (decoded.publicKey.type === 'RSA' && decoded.publicKey.rsa) {
    output += `\tType: RSA\n`;
    output += `\tModulus (n): ${decoded.publicKey.rsa.modulus}\n`;
    output += `\tExponent (e): ${decoded.publicKey.rsa.exponent}\n`;
  } else if (decoded.publicKey.type === 'ECDSA' && decoded.publicKey.ecdsa) {
    output += `\tType: ECDSA\n`;
    output += `\tCurve OID: ${decoded.publicKey.ecdsa.curveOID}\n`;
    output += `\tPublic Key: ${decoded.publicKey.ecdsa.publicKeyHex}\n`;
  }
  if (decoded.extensions) {
    output += 'Extensions:\n';
    for (const ext of decoded.extensions) {
      const parsedExtText = prettyPrintExtension(ext);
      output += `\t${parsedExtText}\n\n`;
    }
  }
  output += '\n\n' + '~'.repeat(50) + '\n';
  output += '\nPEM Content:\n\n';
  output += decoded.decodedPem || '';
  return output;
}

function formatExtensionText(ext: ParsedExtension, tabSize = 2): string {
  const lines: string[] = [];

  lines.push(`${ext.name} ${ext.critical ? '(critical)' : ''}`.trim());

  if (ext.parsed) {
    for (const [key, val] of Object.entries(ext.parsed)) {
      const label = key.replace(/([A-Z])/g, '$1').replace(/^./, s => s.toUpperCase());
      const value = typeof val === 'boolean' ? (val ? 'Yes' : 'No') : val;
      lines.push(`\t`.repeat(tabSize) + `- ${label}: ${value}`);
    }
  } else if (ext.raw) {
    lines.push(`- Raw Value: ${btoa(ext.raw)}`);
  }

  if (ext.warnings?.length) {
    for (const warning of ext.warnings) {
      lines.push(`- Warning: ${warning}`);
    }
  }

  return lines.join('\n');
}

/**
 * Parses an extexsion and, if supported, decodes its ASN.1 value into readable text.
 * @param ext The extension (name, value, critical?)
 * @returns
 */
function prettyPrintExtension(ext: { name: string; binaryValue: string; critical?: boolean }): any {
  let parsed = null;
  switch (ext.name) {
    case 'basicConstraints': {
      parsed = parseBasicConstraints({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    case 'keyUsage': {
      parsed = parseKeyUsage({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    case 'subjectAltName': {
      parsed = parseSubjectAltName({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    case 'extendedKeyUsage': {
      parsed = parseExtendedKeyUsage({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    case 'subjectKeyIdentifier': {
      parsed = parseSubjectKeyIdentifier({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    case 'authorityKeyIdentifier': {
      parsed = parseAuthorityKeyIdentifier({
        name: ext.name,
        binaryValue: ext.binaryValue,
        critical: ext.critical,
      });
      break;
    }
    default: {
      const base64 = btoa(ext.binaryValue);
      return `${ext.name} ${ext.critical ? '(critical)' : ''}
        - Parsing not yet supported — coming soon!
        - Raw (base64): ${base64}`;
    }
  }
  return formatExtensionText(parsed);
}
