import { fromBER, OctetString, Integer } from 'asn1js';
import { ParsedExtension } from '../../types';
import { bufferToHexCodes } from 'pvutils';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

/**
 * Parses and decodes an Authority Key Identifier extension.
 *     AuthorityKeyIdentifier ::= SEQUENCE {
 *         keyIdentifier             [0] IMPLICIT OCTET STRING OPTIONAL,
 *         authorityCertIssuer      [1] IMPLICIT GeneralNames OPTIONAL,
 *         authorityCertSerialNumber [2] IMPLICIT INTEGER OPTIONAL
 *     }
 *
 * @param ext The extension to parse and decode.
 * @returns The parsed Authority Key Identifier extension.
 */
export function parseAuthorityKeyIdentifier(ext: {
  name: string;
  binaryValue: string;
  critical?: boolean;
}): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Authority Key Identifier',
    oid: '2.5.29.35',
    critical: !!ext.critical,
    type: 'authorityKeyIdentifier',
    parsed: {},
  };

  try {
    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const seq = asn1.valueBlock.value;

    for (const item of seq) {
      const tag = item.idBlock.tagNumber;

      if (tag === 0 && item instanceof OctetString) {
        result.parsed!.keyIdentifier = bufferToHexCodes(item.valueBlock.valueHex);
      } else if (tag === 2 && item instanceof Integer) {
        result.parsed!.authorityCertSerialNumber = item.valueBlock.valueDec.toString();
      } else if (tag === 1) {
        result.parsed!.authorityCertIssuer = '[GeneralNames parsing not yet implemented]';
      }
    }
  } catch (err) {
    result.warnings = ['Exception during Authority Key Identifier decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
