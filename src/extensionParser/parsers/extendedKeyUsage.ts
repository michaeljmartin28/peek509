import { fromBER, ObjectIdentifier } from 'asn1js';
import { ParsedExtension } from '../../types';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

const ekuPurposeMap: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '1.3.6.1.4.1.311.10.3.4': 'Microsoft Encrypting File System',
  '1.3.6.1.4.1.311.20.2.2': 'Microsoft Smartcard Logon',
  // Add more as needed
};

/**
 * Parses and decodes an Extended Key Usage extension.
 *     ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *     KeyPurposeId ::= OBJECT IDENTIFIER
 *
 * @param ext The extension to parse and decode.
 * @returns The parsed Extended Key Usage extension.
 */
export function parseExtendedKeyUsage(ext: { name: string; binaryValue: string; critical?: boolean }): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Extended Key Usage',
    oid: '2.5.29.37',
    critical: !!ext.critical,
    type: 'extendedKeyUsage',
    parsed: {},
  };

  try {
    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const oids = (asn1.valueBlock as any).value;
    for (const oidNode of oids) {
      if (oidNode instanceof ObjectIdentifier) {
        const oid = oidNode.valueBlock.toString();
        const label = ekuPurposeMap[oid] ?? `Unknown (${oid})`;
        result.parsed![label] = true;
      }
    }
  } catch (err) {
    result.warnings = ['Exception during EKU decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
