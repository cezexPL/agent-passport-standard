import type { AnchorReceipt, AnchorVerification, ProviderInfo, AnchorMetadata } from './types.js';
import { bytesToHex } from '@noble/hashes/utils';

export interface AnchorProvider {
  commit(hash: Uint8Array, meta: AnchorMetadata): Promise<AnchorReceipt>;
  verify(hash: Uint8Array): Promise<AnchorVerification>;
  info(): ProviderInfo;
}

export class NoopAnchor implements AnchorProvider {
  async commit(hash: Uint8Array, _meta: AnchorMetadata): Promise<AnchorReceipt> {
    return {
      tx_hash: '0x' + bytesToHex(hash),
      block: 1,
      timestamp: new Date().toISOString(),
      provider: 'noop',
    };
  }

  async verify(hash: Uint8Array): Promise<AnchorVerification> {
    return {
      exists: true,
      tx_hash: '0x' + bytesToHex(hash),
      block: 1,
      timestamp: new Date().toISOString(),
    };
  }

  info(): ProviderInfo {
    return { name: 'noop', chain_id: '0', type: 'noop' };
  }
}
