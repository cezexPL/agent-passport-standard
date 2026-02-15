import { describe, it, expect } from 'vitest';
import { ArweaveAnchor } from '../src/anchor_arweave.js';

describe('ArweaveAnchor', () => {
  it('should commit a hash', async () => {
    const fetch = async () =>
      ({ json: async () => ({ id: 'arweave-tx-12345' }) }) as Response;
    const provider = new ArweaveAnchor({ gatewayUrl: 'http://mock' }, fetch as typeof globalThis.fetch);
    const hash = new Uint8Array(32).fill(1);
    const receipt = await provider.commit(hash, { artifact_type: 'passport', description: '' });
    expect(receipt.tx_hash).toBe('arweave-tx-12345');
    expect(receipt.provider).toBe('arweave');
  });

  it('should verify found hash', async () => {
    const fetch = async () =>
      ({
        json: async () => ({
          data: {
            transactions: {
              edges: [{ node: { id: 'ar-tx-123', block: { height: 100, timestamp: 1700000000 } } }],
            },
          },
        }),
      }) as Response;
    const provider = new ArweaveAnchor({ gatewayUrl: 'http://mock' }, fetch as typeof globalThis.fetch);
    const v = await provider.verify(new Uint8Array(32).fill(1));
    expect(v.exists).toBe(true);
    expect(v.tx_hash).toBe('ar-tx-123');
    expect(v.block).toBe(100);
  });

  it('should return false for not found hash', async () => {
    const fetch = async () =>
      ({
        json: async () => ({ data: { transactions: { edges: [] } } }),
      }) as Response;
    const provider = new ArweaveAnchor({ gatewayUrl: 'http://mock' }, fetch as typeof globalThis.fetch);
    const v = await provider.verify(new Uint8Array(32).fill(1));
    expect(v.exists).toBe(false);
  });

  it('should return correct info', () => {
    const provider = new ArweaveAnchor();
    const info = provider.info();
    expect(info.name).toBe('arweave');
    expect(info.type).toBe('arweave');
  });
});
