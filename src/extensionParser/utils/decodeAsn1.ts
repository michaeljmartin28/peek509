import * as asn1js from 'asn1js';

export function decodeExtensionAsn1(binaryValue: string): {
  asn1: asn1js.BaseBlock | null;
  buffer: Uint8Array;
  error?: string;
} {
  const buffer = new Uint8Array(binaryValue.length);
  for (let i = 0; i < binaryValue.length; i++) {
    buffer[i] = binaryValue.charCodeAt(i);
  }

  const asn1 = asn1js.fromBER(buffer.buffer);
  if (asn1.offset === -1) {
    return { asn1: null, buffer, error: 'Failed to decode ASN.1' };
  }

  return { asn1: asn1.result, buffer };
}
