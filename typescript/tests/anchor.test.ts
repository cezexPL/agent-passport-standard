import { describe, it, expect } from 'vitest';
import { NoopAnchor } from '../src/anchor.js';

describe('NoopAnchor', () => {
  it('commit returns receipt with tx_hash', async () => {
    const anchor = new NoopAnchor();
    const hash = new Uint8Array(32).fill(0xab);
    const receipt = await anchor.commit(hash, { artifact_type: 'passport', description: 'test' });

    expect(receipt.tx_hash).toMatch(/^0x/);
    expect(receipt.block).toBe(1);
    expect(receipt.provider).toBe('noop');
  });

  it('verify returns exists=true', async () => {
    const anchor = new NoopAnchor();
    const hash = new Uint8Array(32).fill(0xab);
    const result = await anchor.verify(hash);

    expect(result.exists).toBe(true);
    expect(result.tx_hash).toMatch(/^0x/);
  });

  it('info returns noop provider', () => {
    const anchor = new NoopAnchor();
    const info = anchor.info();
    expect(info.name).toBe('noop');
    expect(info.type).toBe('noop');
  });
});
