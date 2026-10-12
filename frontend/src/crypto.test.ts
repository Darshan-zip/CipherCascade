import { describe, expect, it } from 'vitest';
import { decryptMessage, encryptMessage, randomSequence } from './crypto';

const context = { cid: 'conversation-1', sender: 'alice', secret: 'a sufficiently long shared experimental phrase' };

describe('algorithm registry cascade', () => {
  it.each([
    [1], [2], [3], [4], [5], [1, 2], [3, 2, 1], [4, 1, 5, 2], [1, 2, 3, 4, 5],
  ].map(sequence => ({ sequence })))('round trips sequence $sequence', async ({ sequence }) => {
    const message = 'CipherCascade test: नमस्ते 🔐';
    const packet = await encryptMessage(message, sequence as any, context.cid, context.sender, 42, context.secret);
    expect(packet.algorithm_sequence).toEqual(sequence);
    expect(await decryptMessage(packet, context.cid, context.sender, context.secret)).toBe(message);
  });

  it('generates CSPRNG sequences with length 1–5 and IDs 1–5', () => {
    for (let i = 0; i < 200; i++) {
      const seq = randomSequence();
      expect(seq.length).toBeGreaterThanOrEqual(1);
      expect(seq.length).toBeLessThanOrEqual(5);
      expect(seq.every(id => id >= 1 && id <= 5)).toBe(true);
    }
  });

  it.each(['sequence', 'number', 'nonce', 'ciphertext', 'ctr-tag'] as const)('rejects tampered %s', async kind => {
    const packet = await encryptMessage('do not show partial plaintext', [4, 1], context.cid, context.sender, 99, context.secret);
    if (kind === 'sequence') packet.algorithm_sequence = [1, 4];
    if (kind === 'number') packet.message_number++;
    if (kind === 'nonce') packet.layers[0].nonce = 'AAAA';
    if (kind === 'ciphertext') packet.layers[0].ciphertext = 'AAAA';
    if (kind === 'ctr-tag') {
      const ctrPacket = await encryptMessage('secret', [4], context.cid, context.sender, 100, context.secret);
      ctrPacket.layers[0].tag = 'A'.repeat(43);
      await expect(decryptMessage(ctrPacket, context.cid, context.sender, context.secret)).rejects.toThrow();
      return;
    }
    await expect(decryptMessage(packet, context.cid, context.sender, context.secret)).rejects.toThrow();
  });
});
