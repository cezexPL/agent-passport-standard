# §24 Account Abstraction Profile

## 24.1 Overview

This section specifies how APS implementations integrate with ERC-4337 Account Abstraction to provide gas-abstracted identity management for AI agents.

## 24.2 Smart Wallet Requirements

### 24.2.1 Wallet Contract

An APS-compliant smart wallet MUST:

1. Support `execute(address target, uint256 value, bytes calldata data)` for arbitrary calls
2. Support `executeBatch(address[] targets, bytes[] datas)` for batch operations
3. Implement `validateUserOp(UserOperation, bytes32, uint256)` per ERC-4337
4. Be deployable via CREATE2 for deterministic addressing
5. Support 2-step ownership transfer
6. Provide emergency recovery with a minimum 7-day timelock

An APS-compliant smart wallet SHOULD:

1. Be usable without a bundler (direct EOA owner calls)
2. Integrate with `AgentIdentityRegistry` via convenience methods
3. Accept ETH via `receive()`

### 24.2.2 Wallet Factory

The wallet factory MUST:

1. Deploy wallets deterministically: `createWallet(address owner, bytes32 agentId) → address`
2. Provide address prediction: `getWalletAddress(address owner, bytes32 agentId) → address`
3. Prevent duplicate wallets for the same `agentId`
4. Use `salt = keccak256(abi.encodePacked(owner, agentId))` for CREATE2

## 24.3 Paymaster Interface

### 24.3.1 Validation

```solidity
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external returns (bytes memory context, uint256 validationData);
```

The paymaster MUST:

1. Verify the operation targets an allowed contract (whitelist)
2. Enforce per-wallet rate limits
3. Return `context` containing the wallet address for `postOp`

### 24.3.2 Rate Limiting

- Default: 10 operations per wallet per 24-hour period
- Period boundary: `block.timestamp / 86400` (UTC day)
- Configurable by admin via `setMaxOpsPerDay(uint256)`

### 24.3.3 Sponsored Targets

The paymaster SHOULD sponsor:

| Target | Operations |
|--------|-----------|
| AgentIdentityRegistry | registerAgent, anchorSnapshot |
| AgentWalletFactory | createWallet |

## 24.4 Gas Abstraction Security Considerations

### 24.4.1 Signature Validation

- `validateUserOp` MUST recover the signer from `userOp.signature` using ECDSA
- The recovered address MUST match the wallet owner
- Invalid signatures MUST return `SIG_VALIDATION_FAILED (1)`

### 24.4.2 Paymaster Drain Prevention

- Rate limiting prevents a single wallet from exhausting paymaster funds
- Only whitelisted contract targets receive sponsorship
- Admin can withdraw funds and adjust limits

### 24.4.3 Ownership Security

- Ownership transfer requires acceptance by the new owner (2-step)
- Emergency recovery has a 7-day delay, cancellable by the current owner
- Both mechanisms prevent unauthorized wallet takeover

### 24.4.4 Cross-Chain Considerations

- Wallet state is NOT synchronized across chains
- Each chain has independent ownership and nonce state
- The same deterministic address does NOT imply the same owner on different chains unless the factory deployment is coordinated
