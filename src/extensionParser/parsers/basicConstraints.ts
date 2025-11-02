import { fromBER, Sequence, Boolean as ASN1Boolean, Integer } from 'asn1js';
import { ParsedExtension } from '../../types';
import { decodeExtensionAsn1 } from '../utils/decodeAsn1';

/**
 * Parses and decodes a Basic Constraints extension based on the definition in RFC 5280.
 *    BasicConstraints ::= SEQUENCE {
 *       cA                      BOOLEAN DEFAULT FALSE,
 *       pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
 * @param ext The extension to parse and decode.
 * @returns The parsed Basic Constraints extension.
 */
export function parseBasicConstraints(ext: { name: string; binaryValue: string; critical?: boolean }): ParsedExtension {
  const result: ParsedExtension = {
    name: 'Basic Constraints',
    oid: '2.5.29.19',
    critical: !!ext.critical,
    type: 'basicConstraints',
    parsed: {},
  };

  try {
    const { asn1, buffer, error } = decodeExtensionAsn1(ext.binaryValue);
    if (error || !asn1) {
      result.warnings = [error ?? 'Unknown decoding error'];
      result.raw = ext.binaryValue;
      return result;
    }

    const values = asn1.valueBlock.value;

    if (values.length > 0 && values[0] instanceof ASN1Boolean) {
      result.parsed!.isCA = values[0].getValue();
    } else {
      result.parsed!.isCA = false;
    }

    if (values.length > 1 && values[1] instanceof Integer) {
      result.parsed!.pathLenConstraint = values[1].valueBlock.valueDec;
    }
  } catch (err) {
    console.log(err);
    result.warnings = ['Exception during ASN.1 decoding'];
    result.raw = ext.binaryValue;
  }

  return result;
}
