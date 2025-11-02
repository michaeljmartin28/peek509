import { fromBER, BitString } from 'asn1js';
import { ParsedExtension } from '../../types';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

const usageFlags = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
];

/**
 * Parses and decodes a Key Usage extension based on the definition in RFC 5280.
 *     KeyUsage ::= BIT STRING {
 *         digitalSignature        (0),
 *         nonRepudiation          (1),
 *         keyEncipherment         (2),
 *         dataEncipherment        (3),
 *         keyAgreement            (4),
 *         keyCertSign             (5),
 *         cRLSign                 (6),
 *         encipherOnly            (7),
 *         decipherOnly            (8)
 *     }
 *
 * @param ext The extension to parse and decode.
 * @returns The parsed Key Usage extension.
 */
export function parseKeyUsage(ext: { name: string; binaryValue: string; critical?: boolean }): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Key Usage',
    oid: '2.5.29.15',
    critical: !!ext.critical,
    type: 'keyUsage',
    parsed: {},
  };

  try {
    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const bits = (asn1.valueBlock as any).valueHex;
    const bitArray = new Uint8Array(bits);

    // Flatten bits into a single array of booleans
    const flags: boolean[] = [];
    for (let byte of bitArray) {
      for (let i = 7; i >= 0; i--) {
        flags.push((byte >> i) & 1 ? true : false);
      }
    }

    usageFlags.forEach((name, index) => {
      result.parsed![name] = flags[index] || false;
    });
  } catch (err) {
    result.warnings = ['Exception during BIT STRING decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
