import type { AnchorReceipt, AnchorVerification, ProviderInfo, AnchorMetadata } from './types.js';
import type { AnchorProvider } from './anchor.js';
import { bytesToHex } from '@noble/hashes/utils';

export interface EthereumConfig {
  rpcUrl: string;
  contractAddress: string;
  chainId?: string;
  fromAddress?: string;
  privateKey?: string;
}

// anchor(bytes32) selector
const ANCHOR_SELECTOR = '0xc2b12a73';
// isAnchored(bytes32) selector
const IS_ANCHORED_SELECTOR = '0xa85f7489';

interface JsonRpcResponse {
  jsonrpc: string;
  result?: unknown;
  error?: { code: number; message: string };
  id: number;
}

export class EthereumAnchor implements AnchorProvider {
  private cfg: EthereumConfig;
  private _fetch: typeof globalThis.fetch;

  constructor(cfg: EthereumConfig, fetchFn?: typeof globalThis.fetch) {
    this.cfg = cfg;
    this._fetch = fetchFn || globalThis.fetch;
  }

  private async rpcCall(method: string, params: unknown[]): Promise<unknown> {
    const body = JSON.stringify({ jsonrpc: '2.0', method, params, id: 1 });
    const resp = await this._fetch(this.cfg.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    const data: JsonRpcResponse = await resp.json();
    if (data.error) throw new Error(`RPC error: ${data.error.message}`);
    return data.result;
  }

  async commit(hash: Uint8Array, _meta: AnchorMetadata): Promise<AnchorReceipt> {
    const hashHex = bytesToHex(hash);
    const data = ANCHOR_SELECTOR + hashHex.padEnd(64, '0').slice(0, 64);
    const tx = { from: this.cfg.fromAddress || '', to: this.cfg.contractAddress, data };
    const txHash = (await this.rpcCall('eth_sendTransaction', [tx])) as string;

    let block = 0;
    try {
      const receipt = (await this.rpcCall('eth_getTransactionReceipt', [txHash])) as {
        blockNumber?: string;
      } | null;
      if (receipt?.blockNumber) {
        block = parseInt(receipt.blockNumber, 16);
      }
    } catch {
      // ignore
    }

    return {
      tx_hash: txHash,
      block,
      timestamp: new Date().toISOString(),
      provider: 'ethereum',
    };
  }

  async verify(hash: Uint8Array): Promise<AnchorVerification> {
    const hashHex = bytesToHex(hash);
    const data = IS_ANCHORED_SELECTOR + hashHex.padEnd(64, '0').slice(0, 64);
    const call = { to: this.cfg.contractAddress, data };
    const result = (await this.rpcCall('eth_call', [call, 'latest'])) as string;

    const clean = result.replace('0x', '');
    const isAnchored = clean.length >= 64 && clean[63] === '1';

    if (!isAnchored) return { exists: false };
    return { exists: true, timestamp: new Date().toISOString() };
  }

  info(): ProviderInfo {
    return { name: 'ethereum', chain_id: this.cfg.chainId || '1', type: 'ethereum' };
  }
}
