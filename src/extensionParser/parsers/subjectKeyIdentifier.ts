import { fromBER, OctetString } from 'asn1js';
import { ParsedExtension } from '../../types';
import { bufferToHexCodes } from 'pvutils';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

/**
 * Parses and decodes a Subject Key Identifier extension.
 *     SubjectKeyIdentifier ::= OCTET STRING
 *
 * @param ext The extension to parse and decode.
 * @returns The parsed Subject Key Identifier extension.
 */
export function parseSubjectKeyIdentifier(ext: {
  name: string;
  binaryValue: string;
  critical?: boolean;
}): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Subject Key Identifier',
    oid: '2.5.29.14',
    critical: !!ext.critical,
    type: 'subjectKeyIdentifier',
    parsed: {},
  };

  try {
    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const keyIdHex = bufferToHexCodes(asn1.valueBlock.valueHex);
    result.parsed!.identifier = keyIdHex;
  } catch (err) {
    result.warnings = ['Exception during Subject Key Identifier decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
