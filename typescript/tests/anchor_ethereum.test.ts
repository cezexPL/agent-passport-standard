import { describe, it, expect } from 'vitest';
import { EthereumAnchor } from '../src/anchor_ethereum.js';

function mockFetch(responses: Record<string, unknown>) {
  return async (_url: string, opts: { body: string }) => {
    const req = JSON.parse(opts.body);
    const result = responses[req.method];
    return {
      json: async () => ({ jsonrpc: '2.0', result, id: 1 }),
    } as Response;
  };
}

describe('EthereumAnchor', () => {
  it('should commit a hash', async () => {
    const fetch = mockFetch({
      eth_sendTransaction: '0xabc123',
      eth_getTransactionReceipt: { blockNumber: '0xa' },
    });
    const provider = new EthereumAnchor(
      { rpcUrl: 'http://mock', contractAddress: '0x1234', fromAddress: '0xaaaa' },
      fetch as typeof globalThis.fetch,
    );
    const hash = new Uint8Array(32).fill(1);
    const receipt = await provider.commit(hash, { artifact_type: 'passport', description: '' });
    expect(receipt.tx_hash).toBe('0xabc123');
    expect(receipt.block).toBe(10);
    expect(receipt.provider).toBe('ethereum');
  });

  it('should verify anchored hash', async () => {
    const trueResult = '0x0000000000000000000000000000000000000000000000000000000000000001';
    const fetch = mockFetch({ eth_call: trueResult });
    const provider = new EthereumAnchor(
      { rpcUrl: 'http://mock', contractAddress: '0x1234' },
      fetch as typeof globalThis.fetch,
    );
    const v = await provider.verify(new Uint8Array(32).fill(1));
    expect(v.exists).toBe(true);
  });

  it('should return false for non-anchored hash', async () => {
    const falseResult = '0x0000000000000000000000000000000000000000000000000000000000000000';
    const fetch = mockFetch({ eth_call: falseResult });
    const provider = new EthereumAnchor(
      { rpcUrl: 'http://mock', contractAddress: '0x1234' },
      fetch as typeof globalThis.fetch,
    );
    const v = await provider.verify(new Uint8Array(32).fill(1));
    expect(v.exists).toBe(false);
  });

  it('should return correct info', () => {
    const provider = new EthereumAnchor({ rpcUrl: 'http://mock', contractAddress: '0x1234', chainId: '8453' });
    const info = provider.info();
    expect(info.name).toBe('ethereum');
    expect(info.chain_id).toBe('8453');
    expect(info.type).toBe('ethereum');
  });
});
