import type { AnchorReceipt, AnchorVerification, ProviderInfo, AnchorMetadata } from './types.js';
import type { AnchorProvider } from './anchor.js';
import { bytesToHex } from '@noble/hashes/utils';

export interface ArweaveConfig {
  gatewayUrl?: string;
}

export class ArweaveAnchor implements AnchorProvider {
  private gatewayUrl: string;
  private _fetch: typeof globalThis.fetch;

  constructor(cfg?: ArweaveConfig, fetchFn?: typeof globalThis.fetch) {
    this.gatewayUrl = cfg?.gatewayUrl || 'https://arweave.net';
    this._fetch = fetchFn || globalThis.fetch;
  }

  async commit(hash: Uint8Array, meta: AnchorMetadata): Promise<AnchorReceipt> {
    const hashHex = '0x' + bytesToHex(hash);
    const tx = {
      data: hashHex,
      tags: [
        { name: 'App-Name', value: 'AgentPassportStandard' },
        { name: 'APS-Hash', value: hashHex },
        { name: 'APS-Type', value: meta.artifact_type },
        { name: 'Content-Type', value: 'text/plain' },
      ],
    };

    const resp = await this._fetch(this.gatewayUrl + '/tx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tx),
    });
    const data = await resp.json();

    return {
      tx_hash: data.id || '',
      block: 0,
      timestamp: new Date().toISOString(),
      provider: 'arweave',
    };
  }

  async verify(hash: Uint8Array): Promise<AnchorVerification> {
    const hashHex = '0x' + bytesToHex(hash);
    const query = {
      query: `query($hash: String!) {
        transactions(tags: [{name: "APS-Hash", values: [$hash]}], first: 1) {
          edges { node { id block { height timestamp } } }
        }
      }`,
      variables: { hash: hashHex },
    };

    const resp = await this._fetch(this.gatewayUrl + '/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
    });
    const data = await resp.json();

    const edges = data?.data?.transactions?.edges || [];
    if (edges.length === 0) return { exists: false };

    const node = edges[0].node;
    return {
      exists: true,
      tx_hash: node.id,
      block: node.block?.height || 0,
      timestamp: node.block?.timestamp
        ? new Date(node.block.timestamp * 1000).toISOString()
        : undefined,
    };
  }

  info(): ProviderInfo {
    return { name: 'arweave', chain_id: 'arweave-mainnet', type: 'arweave' };
  }
}
