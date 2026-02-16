# Account Abstraction — APS Integration Guide

## Overview

The Agent Passport Standard (APS) supports ERC-4337 Account Abstraction, enabling agents to interact with on-chain registries without managing private keys or holding ETH for gas.

## ERC-4337 Integration

### Smart Wallet Pattern

Each agent receives a deterministic smart wallet deployed via a factory contract:

```
AgentWalletFactory.createWallet(ownerAddress, agentId) → walletAddress
```

The wallet address is deterministic (CREATE2), meaning it can be computed before deployment:

```
AgentWalletFactory.getWalletAddress(ownerAddress, agentId) → predictedAddress
```

### Wallet Capabilities

| Function | Description |
|----------|-------------|
| `execute(target, value, data)` | Execute arbitrary call (owner only) |
| `executeBatch(targets, datas)` | Batch multiple calls |
| `validateUserOp(userOp, hash, funds)` | ERC-4337 validation |
| `registerSelf(registry, snapshotHash)` | Register agent on-chain |
| `anchorSnapshot(registry, version, hash, prevHash)` | Anchor identity snapshot |

### Dual-Mode Operation

1. **Direct Mode**: Owner EOA calls wallet functions directly. No bundler needed.
2. **ERC-4337 Mode**: UserOperations via bundler with paymaster sponsorship.

Implementations SHOULD support both modes.

## Wallet Factory Pattern

### Interface

```solidity
interface IAgentWalletFactory {
    function createWallet(address owner, bytes32 agentId) external returns (address);
    function getWalletAddress(address owner, bytes32 agentId) external view returns (address);
}
```

### Deterministic Addressing

The salt is `keccak256(abi.encodePacked(owner, agentId))`. Implementations MUST use CREATE2 for deterministic deployment.

## Paymaster Integration

A paymaster MAY sponsor gas for APS-related operations:

- Agent registration
- Snapshot anchoring
- Wallet creation

Implementations SHOULD rate-limit sponsored operations to prevent abuse.

## Cross-Chain Wallet Portability

Since wallet addresses are deterministic based on `(factory, owner, agentId)`:

1. Deploy the same factory bytecode on each chain
2. Same `(owner, agentId)` pair → same wallet address across chains
3. Agent identity is portable: same wallet address on Base, Ethereum, Arbitrum, etc.

### Requirements for Cross-Chain Portability

- Factory MUST be deployed at the same address on all chains (use CREATE2 deployer)
- Wallet bytecode MUST be identical across chains
- EntryPoint address SHOULD be the canonical ERC-4337 EntryPoint

## Security Considerations

- Wallet ownership transfer uses a 2-step pattern (propose + accept)
- Emergency recovery has a 7-day timelock, cancellable by current owner
- UserOp validation uses ECDSA signature recovery
- Paymaster rate limits prevent gas sponsorship abuse
