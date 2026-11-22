import { describe, expect, it } from 'vitest';
import { errorShape, isPoint, keysetIdV1, keysetIdV2 } from '../src/checks';
import { nut20Digest } from '../src/funded';
import { verifyMintQuoteSignature } from '@cashu/cashu-ts';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';

describe('spec helpers', () => {
  // NUT-02 test vectors
  it('derives a V1 keyset id', () => {
    const keys = {
      '1': '03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc',
      '2': '03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de',
      '4': '02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303',
      '8': '02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528',
    };
    expect(keysetIdV1(keys)).toBe('00456a94ab4e1c46');
  });
  it('derives a V2 keyset id the same way for any key order, and fee/expiry change it', () => {
    const keys = { '2': '03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de', '1': '03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc' };
    const a = keysetIdV2(keys, 'sat');
    expect(a).toMatch(/^01[0-9a-f]{64}$/);
    expect(keysetIdV2({ '1': keys['1'], '2': keys['2'] }, 'SAT')).toBe(a);
    expect(keysetIdV2(keys, 'sat', 0)).toBe(a); // fee 0 is omitted
    expect(keysetIdV2(keys, 'sat', 100)).not.toBe(a);
    expect(keysetIdV2(keys, 'sat', null, 2059210353)).not.toBe(a);
  });
  it('validates points', () => {
    expect(isPoint('03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc')).toBe(true);
    expect(isPoint('04a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc')).toBe(false);
    expect(isPoint('02' + 'ff'.repeat(32))).toBe(false);
    expect(isPoint('nope')).toBe(false);
  });
  it('reads NUT-00 error bodies', () => {
    const ex = (status: number, response: unknown) => ({ method: 'POST', path: '/', status, response });
    expect(errorShape(ex(400, { detail: 'x', code: 11001 }))).toBeNull();
    expect(errorShape(ex(400, { detail: 'x' }))).toMatch(/code/);
    expect(errorShape(ex(500, 'Internal Server Error'))).toMatch(/non-JSON/);
    expect(errorShape(ex(200, {}))).toMatch(/expected an error/);
  });
});

describe('NUT-20', () => {
  it('signs the mint request the way cashu-ts verifies it', () => {
    const sk = schnorr.utils.randomSecretKey();
    const pub = bytesToHex(secp256k1.getPublicKey(sk, true));
    const outs = [{ amount: 4, id: '00ab', B_: '02' + 'a'.repeat(64) }, { amount: 1, id: '00ab', B_: '03' + 'b'.repeat(64) }];
    const sig = bytesToHex(schnorr.sign(nut20Digest('quote-123', outs), sk));
    expect(verifyMintQuoteSignature(pub, 'quote-123', outs as never, sig)).toBe(true);
    expect(verifyMintQuoteSignature(pub, 'quote-124', outs as never, sig)).toBe(false);
  });
});
