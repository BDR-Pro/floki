# FLOKI Token — Economic & Security Audit

**Scope:** all 11 Solidity sources under `contracts/`, plus `scripts/deploy-floki.ts`
**Compiler:** `pragma solidity 0.8.11` (checked arithmetic by default)
**Dependencies:** `@openzeppelin/contracts ^4.3.2`, `@uniswap/v2-periphery ^1.1.0-beta.0`
**Commit audited:** `bbfd130`
**Focus:** supply inflation, fund drainage, transfer locks / honeypot mechanics

> **Note on dependency verification.** `node_modules` is not installed in this checkout, so
> statements about `UniswapV2Router02` / `UniswapV2Pair` internals below are reasoned from the
> canonical published source of those contracts, not from a local copy. Every claim about code in
> *this* repository was verified line-by-line against the files in `contracts/`.

---

## Executive summary

The token core (`FLOKI.sol`) is **sound with respect to supply**: there is no mint function,
`totalSupply()` is a `pure` constant, and every balance mutation conserves value. **"Creating money"
is not possible.** That is the good news, and it is worth stating plainly because it is the risk the
audit brief ranks first.

The danger in this system is concentrated in the two hot-swappable satellite contracts and in one
missing access-control modifier:

1. **`TreasuryHandlerAlpha.beforeTransferHandler` has no caller restriction.** Anyone can invoke it
   and force the treasury to market-dump its accumulated tax tokens through Uniswap with
   `amountOutMin = 0`. This is a directly exploitable, capital-free griefing vector and a
   capital-backed extraction vector.
2. **`FLOKI.setTaxHandler` / `setTreasuryHandler` accept any address with no tax ceiling, no
   timelock, and no invariant.** The owner can convert the token into a 100%-sell-tax honeypot, or
   freeze all transfers, in one transaction. Every protective rule the current handlers implement
   (e.g. `StaticTaxHandler`'s "tax can only be lowered") is worthless because the handler itself can
   be replaced.
3. **Several one-call configurations permanently disable selling** — including the configuration the
   shipped deploy script actually produces.

### Findings

> **Severities below are standalone ratings.** A companion pass in
> [`ESCALATION_CHAINS.md`](./ESCALATION_CHAINS.md) analyses how these findings compose, and re-rates
> seven of them upward on the strength of a demonstrated chain — including one **new Critical**
> (X-01: anyone can permanently freeze all sells by sending dust to the treasury handler) that none
> of the individual findings, nor the fixes proposed for them here, covers. Escalated ratings are
> marked in the table below. That document also **corrects the L-02 fix recommended here** — do not
> remove `view` from `ITaxHandler.getTax` as written.

| ID | Severity | Title | Location |
|----|----------|-------|----------|
| [C-01](#c-01) | Critical | `beforeTransferHandler` is permissionless — anyone can force a 0-slippage treasury dump | `TreasuryHandlerAlpha.sol:77` |
| [C-02](#c-02) | Critical | Unbounded hot-swappable tax/treasury handlers — 100% tax honeypot & arbitrary freeze | `Floki.sol:312-328`, `Floki.sol:445-462` |
| [C-03](#c-03) | Critical | `priceImpactBasisPoints = 0` or unset `primaryPool` makes every sell revert | `TreasuryHandlerAlpha.sol:91-99`, `:176-186` |
| [H-01](#h-01) | High | `amountOutMin = 0` and `0/0` liquidity minimums on every router call | `TreasuryHandlerAlpha.sol:226-255` |
| [H-02](#h-02) | High | `transferFrom` validates the allowance *after* executing the transfer | `Floki.sol:169-186` |
| [H-03](#h-03) | High → **Critical** ([X-02](./ESCALATION_CHAINS.md#x-02)) | Owner-settable `treasury` that reverts on receive freezes all sells | `TreasuryHandlerAlpha.sol:132`, `:192-202` |
| [H-04](#h-04) | High | `withdraw()` ERC-20 branch always reverts — rescued tokens are unrecoverable | `TreasuryHandlerAlpha.sol:209-220` |
| [H-05](#h-05) | High | `ExponentialTaxHandler` charges 81% on all sells when `primaryPool` is unset; no setter exists | `ExponentialTaxHandler.sol:70-80` |
| [M-01](#m-01) | Medium → **Critical** ([X-03](./ESCALATION_CHAINS.md#x-03)) | Anti-whale tiers are per-transaction and trivially bypassed by splitting | `ExponentialTaxHandler.sol:72-80` |
| [M-02](#m-02) | Medium → **High** ([X-05](./ESCALATION_CHAINS.md#x-05)) | Treasury front-runs the user's own sell, reverting honest slippage-protected trades | `TreasuryHandlerAlpha.sol:77-135` |
| [M-03](#m-03) | Medium | `StaticTaxHandler` constructor has no upper bound; >10,000 bp bricks all taxed transfers | `StaticTaxHandler.sol:34-36` |
| [M-04](#m-04) | Medium → **Critical** ([X-04](./ESCALATION_CHAINS.md#x-04)) | `addExchangePool` can designate an ordinary wallet, enabling targeted taxation | `ExchangePoolProcessor.sol:42-46` |
| [M-05](#m-05) | Medium → **High** ([X-06](./ESCALATION_CHAINS.md#x-06)) | Tax exemptions are not externally readable | `StaticTaxHandler.sol:20`, `ExponentialTaxHandler.sol:21` |
| [M-06](#m-06) | Medium → **High** ([X-06](./ESCALATION_CHAINS.md#x-06)) | Treasury handler is not tax-exempt by default; leaks ETH to LPs on every liquidity add | `scripts/deploy-floki.ts:38-47` |
| [M-07](#m-07) | Medium → **Critical amplifier** ([X-07](./ESCALATION_CHAINS.md#x-07)) | `renounceOwnership` can permanently brick a misconfigured deployment | all `Ownable` contracts |
| [L-01](#l-01) | Low → **Critical** ([X-01](./ESCALATION_CHAINS.md#x-01)) | `require(amount > 0)` violates ERC-20 and breaks integrations | `Floki.sol:442` |
| [L-02](#l-02) | Low | `ITaxHandler.getTax` is `view`, structurally preventing stateful anti-whale logic | `ITaxHandler.sol:16-20` |
| [L-03](#l-03) | Low | `afterTransferHandler` burns ~5,000 gas per transfer to do nothing | `TreasuryHandlerAlpha.sol:143-154` |
| [L-04](#l-04) | Low | Residual router allowance after `_addLiquidity` | `TreasuryHandlerAlpha.sol:244` |
| [L-05](#l-05) | Low | Liquidity ETH split over-allocates relative to the documented formula | `TreasuryHandlerAlpha.sol:113-122` |
| [L-06](#l-06) | Low | Tokens sent to the token contract itself are permanently lost | `Floki.sol:441` |
| [L-07](#l-07) | Low (lenient guard → **Critical** via [X-02](./ESCALATION_CHAINS.md#x-02)) | Single-step `transferOwnership`; no `IERC20Metadata`; `ecrecover` malleability | various |

---

# 1. Supply manipulation & unauthorized inflation

## What is *not* wrong (verified)

I want to be precise here, because this is the category most likely to be over-reported.

**There is no minting function, hidden or otherwise.** The entire supply is written once in the
constructor:

```solidity
// Floki.sol:78-80
_balances[_msgSender()] = totalSupply();
emit Transfer(address(0), _msgSender(), totalSupply());
```

`totalSupply()` (`Floki.sol:111-114`) is `pure` and returns the literal `1e13 * 1e9` = 10^22 base
units (10 trillion tokens at 9 decimals). It reads no storage, so it cannot be changed by any
transaction, by any owner, or by any handler contract. There is no `_mint`, no `_burn`, no rebase,
no reflection index, and no privileged balance setter anywhere in `contracts/`.

**The transfer accounting conserves supply exactly.** In `_transfer` (`Floki.sol:435-465`):

```solidity
uint256 tax = taxHandler.getTax(from, to, amount);
uint256 taxedAmount = amount - tax;       // reverts if tax > amount (0.8.x checked)

_balances[from] -= amount;                // -amount
_balances[to] += taxedAmount;             // +(amount - tax)
if (tax > 0) {
    _balances[address(treasuryHandler)] += tax;   // +tax
}
```

Debits equal credits in every branch, including the `to == address(treasuryHandler)` and
`from == to` self-transfer cases. A malicious tax handler returning `tax > amount` causes the
subtraction on line 448 to revert rather than to wrap — so **even a hostile handler cannot inflate
the supply, only redirect up to 100% of a transfer** (which is finding [C-02](#c-02), a theft
problem, not an inflation problem).

**No unchecked arithmetic on balances.** The only `unchecked` blocks are `Floki.sol:181-183` and
`212-214`, both guarded by an immediately preceding `require` that makes the subtraction safe. The
`uint224` casts on `taxedAmount`/`tax` are safe because `10^22 < 2^224`.

**Governance checkpoint accounting is conservative.** I traced `_moveDelegates` against every path
in `_transfer` and `_delegate`:

- `_transfer` debits `delegates[from]` by `taxedAmount` (line 452) and by `tax` (line 457) —
  totalling exactly `amount`, matching the balance debit.
- The `from == to` short-circuit (`Floki.sol:358-360`) correctly skips *both* the debit and the
  credit, so the net is zero, which is right when sender and recipient share a delegate.
- The `amount == 0` short-circuit (`:364-366`) is correct for pre-emptive delegation.
- The `address(0)` guards (`:368`, `:376`) implement Compound's semantics — votes are only tracked
  for accounts that have explicitly delegated — consistently on both sides.

The invariant `votes[R] == Σ balances[a] for all a where delegates[a] == R` holds across the
constructor (deployer's `delegates` is `address(0)` at mint time, so zero votes is correct) and
every transfer path. **Vote balances cannot be inflated.**

`getVotesAtBlock`'s binary search (`Floki.sol:288-305`) is also correct: `center = upperBound -
(upperBound - lowerBound) / 2` is the ceiling midpoint, and because `center >= lowerBound + 1`
whenever `upperBound > lowerBound`, the `center - 1` on line 300 cannot underflow.

### S-01 (Informational): supply is monotonically non-increasing but `totalSupply()` never reflects it

Tokens can leave circulation permanently — sent to `address(this)` ([L-06](#l-06)), or stranded in
the treasury handler which explicitly refuses to release them ([H-04](#h-04)) — while
`totalSupply()` continues to report 10^22. Downstream consumers (governance quorum math, market-cap
displays, circulating-supply oracles) will over-count. This is not exploitable, but it means
`totalSupply()` is a *maximum* supply, not a live figure, and the NatSpec on line 108-110 correctly
says so while the ERC-20 semantics of the name do not.

---

# 2. Fund theft & unauthorized drainage

<a id="c-01"></a>
## C-01 — CRITICAL — `beforeTransferHandler` is permissionless: anyone can force a zero-slippage treasury dump

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:77-135`

```solidity
function beforeTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external nonReentrant {          // <-- no onlyToken, no access control at all
    benefactor;
    amount;

    if (!_exchangePools.contains(beneficiary)) {
        return;
    }
    // ... sells up to `priceImpactBasisPoints` of the pool with amountOutMin = 0
}
```

The function is `external` with only a *lenient* reentrancy guard. `ITreasuryHandler` declares no
authentication either. The only input that matters is `beneficiary`, and the attacker simply passes
the publicly readable `primaryPool` address (`getExchangePoolAddresses()` returns the whole set).
`benefactor` and `amount` are discarded on lines 83-84.

### Exploit scenario A — capital-free griefing (no flash loan, no inventory)

An attacker deploys a contract that calls, every block:

```solidity
treasuryHandler.beforeTransferHandler(address(0), POOL, 0);
```

Each call forces the treasury to sell `min(balance, 3% × poolTokenReserve)` — the deploy script sets
`priceImpactBasisPoints = 300` — into Uniswap. The treasury pays the 0.3% LP fee plus the full price
impact of its own sale on **every** call, at a cadence and price chosen by the attacker rather than
by market conditions. Cost to the attacker: gas only. There is no minimum-accumulation threshold and
no cooldown in the code, so the treasury can be forced to trade continuously.

**Impact:** all accrued tax revenue is converted at attacker-selected moments. Even with zero
price manipulation, forcing N sequential dumps costs the treasury `N × 0.3%` in LP fees plus
compounding price impact, versus one batched sale.

### Exploit scenario B — sandwich extraction (attacker capital or a FLOKI flash loan)

Atomically, in one transaction:

1. Sell FLOKI into the pool to depress the price (inventory, or flash-borrowed FLOKI from any venue
   that lists it).
2. Call `beforeTransferHandler(address(0), POOL, 0)`. The treasury dumps its capped balance via
   `_swapTokensForEth`, which passes **`amountOutMin = 0`** (`TreasuryHandlerAlpha.sol:234`). There
   is no floor on what it accepts.
3. Buy back. Because the treasury's tokens were added to the pool at an artificially depressed
   price, the attacker's buy-back recovers *more* FLOKI than they sold in step 1.

Steps 1 and 3 approximately cancel for the attacker, minus two 0.3% LP fees. The delta is funded
entirely by the treasury's underpriced sale.

**Impact:** with `amountOutMin = 0` there is **no lower bound on the loss** other than the attacker's
capital. Per invocation the treasury's at-risk position is
`min(accumulatedTax, priceImpactBasisPoints/10000 × poolTokenReserve)` — 3% of the pool's token
reserve at the shipped setting, and up to 14.99% if an owner raises `priceImpactBasisPoints` toward
its cap. Repeated across blocks this reaches **100% of accumulated tax revenue**. Holders are not
directly drained, but every token the tax mechanism collected on their behalf is.

### Fix

Two independent changes are required; neither is sufficient alone.

**(a) Restrict the caller to the token contract:**

```solidity
/// @dev Only the token contract may drive the transfer hooks.
modifier onlyToken() {
    require(
        msg.sender == address(token),
        "TreasuryHandlerAlpha:onlyToken:UNAUTHORIZED: Caller is not the token contract."
    );
    _;
}

function beforeTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external override onlyToken nonReentrant {
    ...
}

function afterTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external override onlyToken nonReentrant {
    ...
}
```

**(b) Bound the swap price.** Restricting the caller removes scenario A and the *unsolicited*
version of scenario B, but an attacker can still sandwich an organic user sell, because the hook
still fires inside a transaction the attacker can wrap. `amountOutMin = 0` must go.

Note that `router.getAmountsOut(...)` computed inside the same call is **not** a fix — it reads the
same manipulated spot reserves and will happily return the manipulated price. The bound has to come
from outside the transaction. The correct construction is a Uniswap V2 cumulative-price (TWAP)
observation:

```solidity
/// @notice Maximum tolerated deviation from the TWAP, in basis points.
uint256 public maxSlippageBasisPoints = 300;

function _swapTokensForEth(uint256 tokenAmount) private {
    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = router.WETH();

    // `twapQuote` must consult a Uniswap V2 price accumulator sampled at least one block ago
    // (e.g. an OracleLibrary consult against `primaryPool`). A same-block spot quote provides
    // no protection, because the attacker set the spot price earlier in this very transaction.
    uint256 fairWeiOut = twapQuote(tokenAmount);
    uint256 minWeiOut = (fairWeiOut * (10000 - maxSlippageBasisPoints)) / 10000;

    token.approve(address(router), tokenAmount);
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        minWeiOut,
        path,
        address(this),
        block.timestamp
    );
}
```

If a TWAP oracle is out of scope, the pragmatic alternative is to stop swapping inside the transfer
hook entirely: accumulate tax tokens, and expose a `processTreasury()` function callable only by a
keeper/owner with an explicit, caller-supplied `amountOutMin` and `deadline`. That moves slippage
control to a party who can compute it off-chain, which is where it belongs.

---

<a id="c-02"></a>
## C-02 — CRITICAL — Unbounded hot-swappable handlers: 100% tax honeypot and arbitrary transfer freeze

**Location:** `contracts/Floki.sol:312-328` (setters), `contracts/Floki.sol:445-462` (call sites)

```solidity
function setTaxHandler(address taxHandlerAddress) external onlyOwner {
    address oldTaxHandlerAddress = address(taxHandler);
    taxHandler = ITaxHandler(taxHandlerAddress);       // no timelock, no bound, no validation
    emit TaxHandlerChanged(oldTaxHandlerAddress, taxHandlerAddress);
}

function setTreasuryHandler(address treasuryHandlerAddress) external onlyOwner {
    address oldTreasuryHandlerAddress = address(treasuryHandler);
    treasuryHandler = ITreasuryHandler(treasuryHandlerAddress);   // same
    emit TreasuryHandlerChanged(oldTreasuryHandlerAddress, treasuryHandlerAddress);
}
```

`_transfer` then trusts both without constraint:

```solidity
treasuryHandler.beforeTransferHandler(from, to, amount);   // arbitrary code, can revert
uint256 tax = taxHandler.getTax(from, to, amount);         // arbitrary code, unbounded return
uint256 taxedAmount = amount - tax;
```

This is the single most important finding for holders, because it **subsumes every protective
mechanism elsewhere in the codebase.** `StaticTaxHandler.setTaxBasisPoints` carefully enforces
"basis points can only be lowered" (`StaticTaxHandler.sol:71-81`) — an excellent design — but the
owner does not need to raise the tax on that handler. They deploy a new one.

### Exploit scenario A — instant honeypot (theft of 100% of sale value)

The owner deploys:

```solidity
contract HoneypotTaxHandler is ITaxHandler {
    address public immutable pool;
    address public immutable owner;
    constructor(address p, address o) { pool = p; owner = o; }

    function getTax(address benefactor, address beneficiary, uint256 amount)
        external view override returns (uint256)
    {
        if (benefactor == owner) return 0;          // owner exits at 0%
        if (beneficiary == pool) return amount;     // everyone else sells at 100%
        return 0;                                   // wallet-to-wallet still works, so it looks fine
    }
}
```

One `setTaxHandler` call. Buys succeed. Wallet transfers succeed. Every honest sell transfers 100%
of the amount to the treasury handler, and the seller receives zero tokens at the pool — the
Uniswap swap then reverts on `INSUFFICIENT_OUTPUT_AMOUNT`, or, on the fee-on-transfer path,
completes with the seller receiving nothing. The owner sells freely throughout.

**Impact:** total loss of the entire circulating float's exit value. Every holder's position becomes
unsellable; the ETH side of the pool is claimed exclusively by the owner. There is no on-chain
signal before the fact — `TaxHandlerChanged` fires in the same transaction the trap arms.

### Exploit scenario B — arbitrary per-address freeze (blacklist)

The same handler returning `amount + 1` for a targeted address makes line 448
(`amount - tax`) underflow and revert. The victim's tokens are frozen in place with no `Blacklisted`
event, no state in the token contract, and no way for a block explorer to enumerate who is affected.
Returning `amount + 1` unconditionally freezes **all** transfers globally.

### Exploit scenario C — global pause with no timelock

A treasury handler whose `beforeTransferHandler` is `revert()` halts every transfer in the token,
permanently and instantly. There is no pause event, no maximum pause duration, and no governance
gate — the audit brief asks specifically about "pausable functions that can indefinitely block token
transfers without timelocks," and this is a strictly stronger version of that: an *undeclared*
pause with unlimited duration.

### Fix

Three layers, in order of importance.

**(1) Enforce a hard tax ceiling in the token itself.** This is the highest-value single line in
this report: it makes a 100%-tax honeypot impossible regardless of which handler is installed, now
or ever.

```solidity
/// @notice The absolute maximum tax, in basis points, that any tax handler may ever levy.
/// @dev Immutable by construction — it is a compile-time constant, not owner-settable.
uint256 public constant MAX_TAX_BASIS_POINTS = 1000; // 10%

function _transfer(address from, address to, uint256 amount) private {
    ...
    uint256 tax = taxHandler.getTax(from, to, amount);
    require(
        tax <= (amount * MAX_TAX_BASIS_POINTS) / 10000,
        "FLOKI:_transfer:TAX_TOO_HIGH: Tax exceeds the protocol maximum."
    );
    uint256 taxedAmount = amount - tax;
    ...
}
```

**(2) Make the treasury hook non-fatal**, so no handler can freeze transfers:

```solidity
// A failing treasury handler must never be able to lock holders out of their tokens.
// The gas cap also prevents a handler from griefing transfers by burning the whole budget.
try treasuryHandler.beforeTransferHandler{ gas: 500000 }(from, to, amount) {} catch {}
...
try treasuryHandler.afterTransferHandler{ gas: 500000 }(from, to, amount) {} catch {}
```

Trade-off, stated explicitly: this means a genuinely broken treasury handler silently stops
collecting revenue instead of halting the token. For a holder-facing token that is the correct
direction, but it is a deliberate protocol decision, not a pure bug fix — decide it consciously.

**(3) Timelock the handler swaps** so holders can observe and exit:

```solidity
uint256 public constant HANDLER_CHANGE_DELAY = 2 days;

address public pendingTaxHandler;
uint256 public pendingTaxHandlerReadyAt;

event TaxHandlerChangeQueued(address newAddress, uint256 readyAt);

function queueTaxHandler(address taxHandlerAddress) external onlyOwner {
    require(taxHandlerAddress != address(0), "FLOKI:queueTaxHandler:ZERO_ADDRESS");
    pendingTaxHandler = taxHandlerAddress;
    pendingTaxHandlerReadyAt = block.timestamp + HANDLER_CHANGE_DELAY;

    emit TaxHandlerChangeQueued(taxHandlerAddress, pendingTaxHandlerReadyAt);
}

function commitTaxHandler() external onlyOwner {
    require(pendingTaxHandler != address(0), "FLOKI:commitTaxHandler:NOTHING_QUEUED");
    require(
        block.timestamp >= pendingTaxHandlerReadyAt,
        "FLOKI:commitTaxHandler:TIMELOCKED: Change is not yet executable."
    );

    address oldTaxHandlerAddress = address(taxHandler);
    taxHandler = ITaxHandler(pendingTaxHandler);
    pendingTaxHandler = address(0);

    emit TaxHandlerChanged(oldTaxHandlerAddress, address(taxHandler));
}
```

Apply the identical pattern to `setTreasuryHandler`. The NatSpec in `StaticTaxHandler.sol:13-14`
already advises that the owner "should be set to a DAO-controlled timelock or at the very least a
multisig wallet" — that advice is correct and should be enforced in code, and the deploy script
(`scripts/deploy-floki.ts:20-21`) currently leaves ownership with `signers[0]`, a plain EOA.

---

<a id="h-01"></a>
## H-01 — HIGH — Zero slippage bounds and `block.timestamp` deadlines on every router call

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:226-255`

```solidity
router.swapExactTokensForETHSupportingFeeOnTransferTokens(tokenAmount, 0, path, address(this), block.timestamp);
//                                                                     ^ amountOutMin

// Both minimum values are set to zero to allow for any form of slippage.
router.addLiquidityETH{ value: weiAmount }(address(token), tokenAmount, 0, 0, address(treasury), block.timestamp);
//                                                                      ^  ^ amountTokenMin, amountETHMin
```

The comment on line 246 states the intent — "to allow for any form of slippage" — which is precisely
the problem. Reformulated: *this contract will accept any price at all, including zero.*

`deadline = block.timestamp` is also a no-op: it is evaluated at execution time and is therefore
always satisfied, so it provides none of the stale-transaction protection it appears to.

**Economic impact, quantified.** At the shipped `priceImpactBasisPoints = 300`, a single swap moves
3% of the pool's token reserve. Against a constant-product pool this is ~2.9% of the ETH reserve at
fair price and ~5.7% spot impact — but with `amountOutMin = 0` the *realized* price is bounded only
by the sandwicher's capital, not by the pool. Standard sandwich extraction against a zero-minimum
victim recovers the large majority of the trade's value; the treasury's realized ETH can be a small
fraction of fair value, with the difference captured by the attacker. Because [C-01](#c-01) lets the
attacker choose *when* this fires, the two findings compose into a repeatable extraction loop.

`addLiquidityETH` with `0, 0` is exploitable in the same way: the LP position (minted to `treasury`,
line 252) is created at whatever reserve ratio the attacker has set, so the treasury contributes
value at a manipulated price and the imbalance accrues to existing LPs.

**Fix:** as in [C-01](#c-01)(b), plus for liquidity additions:

```solidity
function _addLiquidity(uint256 tokenAmount, uint256 weiAmount) private {
    token.approve(address(router), tokenAmount);

    uint256 minTokens = (tokenAmount * (10000 - maxSlippageBasisPoints)) / 10000;
    uint256 minWei = (weiAmount * (10000 - maxSlippageBasisPoints)) / 10000;

    router.addLiquidityETH{ value: weiAmount }(
        address(token),
        tokenAmount,
        minTokens,
        minWei,
        address(treasury),
        block.timestamp
    );

    // Revoke any residual allowance the router did not consume — see L-04.
    token.approve(address(router), 0);
}
```

---

<a id="h-02"></a>
## H-02 — HIGH — `transferFrom` validates the allowance *after* executing the transfer

**Location:** `contracts/Floki.sol:169-186`

```solidity
function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {
    _transfer(sender, recipient, amount);        // <-- effects + THREE external calls happen first

    uint256 currentAllowance = _allowances[sender][_msgSender()];
    require(currentAllowance >= amount, "FLOKI:transferFrom:ALLOWANCE_EXCEEDED: ...");
    unchecked {
        _approve(sender, _msgSender(), currentAllowance - amount);
    }

    return true;
}
```

This inverts checks-effects-interactions. `_transfer` performs three external calls
(`beforeTransferHandler`, `getTax`, `afterTransferHandler`) and mutates balances **before** the
allowance is read or decremented.

**Why it matters.** The allowance is not decremented until after all reentrancy opportunities have
passed. A reentrant call into `transferFrom` with the same `(sender, spender)` pair — reached from
inside any of those three hooks — reads the *undecremented* allowance and can spend it again. The
recursion terminates when balances run out, not when the allowance does.

With the handlers as currently written this is not reachable: `TreasuryHandlerAlpha`'s nested router
call moves tokens from `address(this)`, not from an arbitrary `sender`. But the handlers are
owner-replaceable in one transaction ([C-02](#c-02)), and `LenientReentrancyGuard` deliberately
*silently returns* rather than reverting on reentry (`LenientReentrancyGuard.sol:38-40`), so the
token core is relying on a property of a contract it does not control and cannot pin. Any future
handler that calls back into `transferFrom` on a user's behalf turns this into a direct
allowance-drain.

Independently, spending an allowance that was never validated to exist — and only discovering that
after emitting `Transfer` events and running third-party code — is the wrong ordering under any
threat model.

**Fix:** check and decrement first, and add the conventional infinite-approval exemption:

```solidity
function transferFrom(
    address sender,
    address recipient,
    uint256 amount
) external override returns (bool) {
    uint256 currentAllowance = _allowances[sender][_msgSender()];
    require(
        currentAllowance >= amount,
        "FLOKI:transferFrom:ALLOWANCE_EXCEEDED: Transfer amount exceeds allowance."
    );

    // An allowance of `type(uint256).max` is treated as infinite and is not decremented.
    if (currentAllowance != type(uint256).max) {
        unchecked {
            _approve(sender, _msgSender(), currentAllowance - amount);
        }
    }

    _transfer(sender, recipient, amount);

    return true;
}
```

---

<a id="h-04"></a>
## H-04 — HIGH — `withdraw()` ERC-20 branch always reverts; rescued tokens are unrecoverable

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:209-220`

```solidity
function withdraw(address tokenAddress, uint256 amount) external onlyOwner {
    require(tokenAddress != address(token), "TreasuryHandlerAlpha:withdraw:INVALID_TOKEN: ...");

    if (tokenAddress == address(0)) {
        treasury.sendValue(amount);
    } else {
        IERC20(tokenAddress).transferFrom(address(this), address(treasury), amount);
        //                   ^^^^^^^^^^^^ pulls from itself; requires a self-allowance that is never set
    }
}
```

`transferFrom(address(this), ...)` requires `allowance[address(this)][address(this)]` to be
non-zero. This contract never calls `approve` on itself for any token other than the router grant in
`_swapTokensForEth`/`_addLiquidity`. OpenZeppelin's `ERC20` — and every standard implementation —
does not special-case `from == msg.sender` in `transferFrom`. **The rescue path therefore reverts
for every standard ERC-20.**

**Impact:** the function that exists specifically to recover stuck funds cannot recover anything.
Any ERC-20 sent to this contract — mistaken user transfers, airdrops, LP tokens if the liquidity
recipient is ever changed, WETH left by a partially-failed swap — is permanently lost. The
`onlyOwner` guard means there is no fallback path. Note also that the return value is unchecked, so
even if the allowance existed, a non-reverting-false token (USDT-family) would report success while
transferring nothing.

**Fix:**

```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract TreasuryHandlerAlpha is ITreasuryHandler, LenientReentrancyGuard, ExchangePoolProcessor {
    using Address for address payable;
    using SafeERC20 for IERC20;                 // handles missing/false return values
    using EnumerableSet for EnumerableSet.AddressSet;

    function withdraw(address tokenAddress, uint256 amount) external onlyOwner {
        require(
            tokenAddress != address(token),
            "TreasuryHandlerAlpha:withdraw:INVALID_TOKEN: Not allowed to withdraw token required for swaps."
        );

        if (tokenAddress == address(0)) {
            treasury.sendValue(amount);
        } else {
            IERC20(tokenAddress).safeTransfer(treasury, amount);
        }
    }
}
```

**Secondary concern on the same function (centralisation, by design but worth stating):** the ETH
branch sends to `treasury`, and `setTreasury` (`:192-202`) is `onlyOwner` with no timelock. An owner
can therefore point the treasury at any address and withdraw. In practice residual ETH here is
small — line 130-133 sweeps the full balance to `treasury` at the end of every successful sell — so
the meaningful exposure is not `withdraw()` but `setTreasury()` itself, which redirects **100% of
all future tax revenue and all LP tokens minted by `_addLiquidity`** (line 252). Timelock it
alongside the handler setters in [C-02](#c-02)(3).

---

<a id="m-06"></a>
## M-06 — MEDIUM — Treasury handler is not tax-exempt by default; every liquidity add leaks ETH to LPs

**Location:** `scripts/deploy-floki.ts:33-47`

The deploy script wires up `ExponentialTaxHandler` and `TreasuryHandlerAlpha` but never calls
`exponentialTaxHandler.addExemption(treasuryHandlerAlpha.address)`, never calls `addExchangePool`,
and never calls `setPrimaryPool`.

With the exemption missing, `_addLiquidity` breaks economically. The router's `addLiquidityETH`
computes `amountToken`/`amountETH` from current reserves, then calls
`transferFrom(treasuryHandler, pair, amountToken)` — which is a transfer **to an exchange pool** and
is therefore taxed. The pair receives less than `amountToken` while the full `amountETH` is
deposited. `UniswapV2Pair.mint` mints `min(tokenSide, ethSide)` LP, so the LP is minted against the
short token side and **the surplus ETH is donated to the pool**, accruing pro-rata to all existing
LPs rather than to the treasury.

**Impact:** at a 3% tax and `liquidityBasisPoints = 2000` (the deploy-script value), roughly 3% of
the ETH allocated to liquidity is silently gifted to third-party LPs on every liquidity addition —
a continuous, systematic bleed exactly matching the "precision loss / fee diversion that
systematically bleeds funds" category in the brief. It is a configuration error rather than a code
error, but the shipped script produces it.

**Fix — complete the deploy script:**

```typescript
// scripts/deploy-floki.ts, after the handlers are deployed:

// The treasury handler sells and adds liquidity on the protocol's behalf. If it is not exempt,
// its own transfers to the pool are taxed, which both double-taxes revenue and causes the
// ETH side of every liquidity addition to be partially donated to third-party LPs.
await exponentialTaxHandler.addExemption(treasuryHandlerAlpha.address);
await exponentialTaxHandler.addExemption(treasury);

// Both processors keep independent pool sets; both must be configured or the system misbehaves
// (see C-03 and H-05).
await exponentialTaxHandler.addExchangePool(pairAddress);
await exponentialTaxHandler.setPrimaryPool(pairAddress);
await treasuryHandlerAlpha.addExchangePool(pairAddress);
await treasuryHandlerAlpha.setPrimaryPool(pairAddress);

// Hand ownership to a timelock/multisig, not the deploying EOA.
await floki.transferOwnership(TIMELOCK);
await exponentialTaxHandler.transferOwnership(TIMELOCK);
await treasuryHandlerAlpha.transferOwnership(TIMELOCK);
```

---

# 3. Transfer locks, blacklisting & honeypot mechanics

<a id="c-03"></a>
## C-03 — CRITICAL — A single owner call, or the default deploy configuration, makes every sell revert

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:91-99` and `:176-186`

```solidity
uint256 contractTokenBalance = token.balanceOf(address(this));
if (contractTokenBalance > 0) {
    uint256 primaryPoolBalance = token.balanceOf(primaryPool);
    uint256 maxPriceImpactSale = (primaryPoolBalance * priceImpactBasisPoints) / 10000;

    if (contractTokenBalance > maxPriceImpactSale) {
        contractTokenBalance = maxPriceImpactSale;      // can become 0
    }

    uint256 tokensForLiquidity = (contractTokenBalance * liquidityBasisPoints) / 20000;
    uint256 tokensForSwap = contractTokenBalance - tokensForLiquidity;
    ...
    _swapTokensForEth(tokensForSwap);                    // called with 0
```

The guard on line 92 tests the balance **before** the clamp, so execution proceeds into the swap even
when the clamp has reduced the amount to zero. `_swapTokensForEth(0)` calls the router, which calls
`TransferHelper.safeTransferFrom(token, treasuryHandler, pair, 0)` — and FLOKI's own `_transfer`
rejects that on line 442:

```solidity
require(amount > 0, "FLOKI:_transfer:ZERO_AMOUNT: Transfer amount must be greater than zero.");
```

The revert propagates all the way up through `beforeTransferHandler` into the user's `_transfer`.
**Every sell reverts, permanently, until an owner intervenes.** Buys are unaffected, because
`beforeTransferHandler` returns early when the beneficiary is not a pool (line 87-89). Buys work,
sells revert: this is the textbook honeypot signature, and here it is reachable by accident.

`maxPriceImpactSale` becomes zero in three distinct ways:

1. **`primaryPool` is never set.** Its default is `address(0)`, `balanceOf(address(0))` is 0. This is
   the state the shipped deploy script leaves the contract in — `scripts/deploy-floki.ts` calls
   neither `addExchangePool` nor `setPrimaryPool` on the treasury handler.
2. **`setPriceImpactBasisPoints(0)`.** The bound is `require(newBasisPoints < 1500)`
   (`:176-180`) — it has **no lower bound**, so zero is accepted. This is a one-transaction,
   fully-permitted, permanent sell-disable switch: precisely the "max transaction limit maliciously
   set to 0 to prevent selling" pattern from the brief, wearing a different name.
3. **A small pool.** `primaryPoolBalance * 300 / 10000` truncates to 0 whenever the pool holds fewer
   than ~34 base units — relevant during the launch window before liquidity is seeded.

Combined with `renounceOwnership` ([M-07](#m-07)), state (1) or (2) becomes **irreversible**.

**Fix:**

```solidity
/// @notice Minimum number of accumulated tokens required before a swap is attempted.
uint256 public minimumSwapThreshold;

function beforeTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external override onlyToken nonReentrant {
    benefactor;
    amount;

    if (!_exchangePools.contains(beneficiary)) {
        return;
    }

    // Nothing can be priced or sold without a primary pool; skip rather than revert, so that a
    // misconfiguration can never lock holders out of selling.
    if (primaryPool == address(0)) {
        return;
    }

    uint256 contractTokenBalance = token.balanceOf(address(this));
    uint256 maxPriceImpactSale = (token.balanceOf(primaryPool) * priceImpactBasisPoints) / 10000;
    uint256 amountToProcess = contractTokenBalance < maxPriceImpactSale
        ? contractTokenBalance
        : maxPriceImpactSale;

    // Never hand a zero (or dust) amount to the router: the token rejects zero-value transfers,
    // which would revert the user's transfer along with it.
    if (amountToProcess < minimumSwapThreshold || amountToProcess == 0) {
        return;
    }

    ...
}
```

and give `setPriceImpactBasisPoints` a floor:

```solidity
function setPriceImpactBasisPoints(uint256 newBasisPoints) external onlyOwner {
    require(
        newBasisPoints >= 10 && newBasisPoints < 1500,
        "TreasuryHandlerAlpha:setPriceImpactBasisPoints:OUT_OF_BOUNDS: Value out of permitted range."
    );
    ...
}
```

The `if (amountToProcess == 0) return;` early exit is the load-bearing line — it converts a
protocol-wide sell freeze into a harmless no-op.

---

<a id="h-03"></a>
## H-03 — HIGH — An owner-settable treasury that reverts on receive freezes all sells

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:130-133`, `:192-202`

```solidity
uint256 remainingWeiBalance = address(this).balance;
if (remainingWeiBalance > 0) {
    treasury.sendValue(remainingWeiBalance);     // Address.sendValue bubbles the callee's revert
}
```

`Address.sendValue` reverts on failure. `treasury` is set by `setTreasury`, `onlyOwner`, with the
only validation being a non-zero check. Setting `treasury` to a contract whose `receive()` reverts
— or one that simply has no payable fallback — makes `beforeTransferHandler` revert on every sell
while leaving buys and wallet transfers working.

This is a second, independent one-call honeypot switch alongside [C-03](#c-03), and it is also an
*accidental* failure mode: an ordinary Gnosis Safe accepts ETH fine, but a treasury contract with a
guard, a paused state, or a token-only receiver would silently brick the token's sell path on
deployment day.

**Fix:** the treasury's ability to receive ETH must never gate holders' ability to transact.

```solidity
uint256 remainingWeiBalance = address(this).balance;
if (remainingWeiBalance > 0) {
    // Deliberately non-reverting: a treasury that cannot accept ETH must not be able to block
    // token transfers. The balance simply stays here and is swept on the next successful sell,
    // and `withdraw` provides a manual escape hatch.
    (bool succeeded, ) = treasury.call{ value: remainingWeiBalance }("");
    succeeded;
}
```

Add `setTreasury` to the timelocked-setter set from [C-02](#c-02)(3).

---

<a id="h-05"></a>
## H-05 — HIGH — `ExponentialTaxHandler` charges 81% on every sell when `primaryPool` is unset, and has no way to lower it

**Location:** `contracts/tax/ExponentialTaxHandler.sol:70-80`

```solidity
uint256 priceImpactBasisPoint = token.balanceOf(primaryPool) / 10000;

if (amount <= priceImpactBasisPoint * 300) {
    return (amount * 300) / 10000;        // 3%
} else if (amount <= priceImpactBasisPoint * 1000) {
    return (amount * 900) / 10000;        // 9%
} else if (amount <= priceImpactBasisPoint * 2000) {
    return (amount * 2700) / 10000;       // 27%
} else {
    return (amount * 8100) / 10000;       // 81%
}
```

When `primaryPool == address(0)` — its default, and the state the deploy script leaves it in —
`priceImpactBasisPoint` is 0, so all three tier comparisons reduce to `amount <= 0`, which is false
for every real transfer. **Execution falls through to the 81% branch for every sell.** The same
happens whenever the pool balance is below 10,000 base units, i.e. during launch.

The chain of events is: pools get registered (enabling taxation), someone forgets `setPrimaryPool`,
and the first seller loses 81% of their tokens to the treasury. The failure direction is exactly
backwards — a missing configuration value should fail *open* to the base rate, never to the maximum
penalty.

Compounding this:

- **There is no setter.** `ExponentialTaxHandler` has `addExemption`/`removeExemption` and nothing
  else. The 3/9/27/81 rates are hardcoded literals. Unlike `StaticTaxHandler`, the owner cannot
  lower them — the only remedy is a full handler swap via [C-02](#c-02).
- **`taxBasisPoints` (line 27) and `TaxBasisPointsUpdated` (line 30) are dead code.** The variable is
  never written or read and permanently reads 0; the event can never be emitted. Anyone inspecting
  the deployed contract on a block explorer to check the tax rate will read `taxBasisPoints = 0`
  and conclude the token is untaxed. That is actively misleading to holders.
- **Commented-out logic** at lines 83-97 (`getImpactTier`) is dead scaffolding with an incorrect
  `amountInBasisPoints = amount / poolBalance` computation. Delete it.

**Fix:**

```solidity
contract ExponentialTaxHandler is ITaxHandler, ExchangePoolProcessor {
    /// @notice Absolute ceiling on any tier, in basis points.
    uint256 public constant MAX_TAX_BASIS_POINTS = 1000;

    /// @notice Tax applied to buys, in basis points.
    uint256 public buyTaxBasisPoints;

    /// @notice Sell tax tiers, in basis points, ordered from the smallest trade size upward.
    uint256[4] public sellTaxBasisPoints;

    /// @notice Tier boundaries expressed in basis points of the primary pool's token reserve.
    uint256[3] public tierBoundaryBasisPoints = [300, 1000, 2000];

    event TaxRatesUpdated(uint256 buyBasisPoints, uint256[4] sellBasisPoints);

    constructor(address tokenAddress, uint256 initialBuyTax, uint256[4] memory initialSellTax) {
        require(initialBuyTax <= MAX_TAX_BASIS_POINTS, "ExponentialTaxHandler:constructor:BUY_TAX_TOO_HIGH");
        for (uint256 i = 0; i < 4; i++) {
            require(
                initialSellTax[i] <= MAX_TAX_BASIS_POINTS,
                "ExponentialTaxHandler:constructor:SELL_TAX_TOO_HIGH"
            );
        }

        token = IERC20(tokenAddress);
        buyTaxBasisPoints = initialBuyTax;
        sellTaxBasisPoints = initialSellTax;
    }

    function getTax(
        address benefactor,
        address beneficiary,
        uint256 amount
    ) external view override returns (uint256) {
        if (_exempted.contains(benefactor) || _exempted.contains(beneficiary)) {
            return 0;
        }
        if (!_exchangePools.contains(benefactor) && !_exchangePools.contains(beneficiary)) {
            return 0;
        }
        if (_exchangePools.contains(benefactor)) {
            return (amount * buyTaxBasisPoints) / 10000;
        }

        uint256 poolBalance = primaryPool == address(0) ? 0 : token.balanceOf(primaryPool);
        uint256 poolBasisPoint = poolBalance / 10000;

        // Fail OPEN, never to the top tier: an unset or dust-sized pool must not punish sellers.
        if (poolBasisPoint == 0) {
            return (amount * sellTaxBasisPoints[0]) / 10000;
        }

        for (uint256 i = 0; i < 3; i++) {
            if (amount <= poolBasisPoint * tierBoundaryBasisPoints[i]) {
                return (amount * sellTaxBasisPoints[i]) / 10000;
            }
        }

        return (amount * sellTaxBasisPoints[3]) / 10000;
    }

    /// @notice Lower the tax rates. Rates can only ever be reduced, never raised.
    function lowerTaxRates(uint256 newBuyTax, uint256[4] calldata newSellTax) external onlyOwner {
        require(newBuyTax <= buyTaxBasisPoints, "ExponentialTaxHandler:lowerTaxRates:HIGHER_VALUE");
        for (uint256 i = 0; i < 4; i++) {
            require(
                newSellTax[i] <= sellTaxBasisPoints[i],
                "ExponentialTaxHandler:lowerTaxRates:HIGHER_VALUE"
            );
            sellTaxBasisPoints[i] = newSellTax[i];
        }
        buyTaxBasisPoints = newBuyTax;

        emit TaxRatesUpdated(newBuyTax, newSellTax);
    }
}
```

Also delete the dead `taxBasisPoints` variable, the unusable `TaxBasisPointsUpdated` event, and the
commented-out `getImpactTier` block.

---

<a id="m-01"></a>
## M-01 — MEDIUM — Anti-whale tiers are per-transaction and trivially bypassed by splitting

**Location:** `contracts/tax/ExponentialTaxHandler.sol:72-80`

The tiers key entirely off the `amount` of a single transfer. A whale wanting to exit 25% of the
pool pays 81% if they do it in one transaction — or 3% if they deploy a two-line contract that loops
sells of 2.9% of the pool each, all inside one transaction. There is no per-address accounting, no
per-block accounting, and no rolling window.

**Impact:** the anti-whale mechanism deters only unsophisticated sellers. The users who pay 27% or
81% are retail holders using a DEX front-end; every party with the ability to deploy a contract pays
3%. This inverts the mechanism's stated purpose (`b954eb3 feat: add tax handler with anti-whale
mechanics`) and produces a regressive tax on exactly the holders it is marketed as protecting. The
splitting loop also multiplies the [C-01](#c-01)/[H-01](#h-01) treasury losses, since each sub-sell
triggers another zero-minimum treasury dump.

**Fix — and a structural blocker.** See [L-02](#l-02): `ITaxHandler.getTax` is declared `view`, so
**no** implementation of this interface can record cumulative volume. Fixing M-01 requires changing
the interface first:

```solidity
// contracts/tax/ITaxHandler.sol — remove `view` so handlers can maintain state.
function getTax(address benefactor, address beneficiary, uint256 amount) external returns (uint256);
```

Then the handler can track a rolling window:

```solidity
struct SellWindow {
    uint128 amount;      // cumulative sold within the current window
    uint128 windowStart; // timestamp the window opened
}

mapping(address => SellWindow) private _sellWindows;
uint256 public constant WINDOW_DURATION = 24 hours;

function _cumulativeSold(address seller, uint256 amount) private returns (uint256) {
    SellWindow storage window = _sellWindows[seller];

    if (block.timestamp >= window.windowStart + WINDOW_DURATION) {
        window.windowStart = uint128(block.timestamp);
        window.amount = 0;
    }

    window.amount += uint128(amount);
    return window.amount;
}
```

and tier on `_cumulativeSold(benefactor, amount)` rather than on `amount`. Note that this changes
`getTax` to a state-mutating call, which means `FLOKI._transfer` can no longer treat it as free and
the gas cost of every taxed transfer rises — a real trade-off to weigh against how much the
anti-whale property is actually worth.

---

<a id="m-02"></a>
## M-02 — MEDIUM — The treasury front-runs the user's own sell, reverting honest slippage-protected trades

**Location:** `contracts/treasury/TreasuryHandlerAlpha.sol:77-135`

The hook fires from inside `FLOKI._transfer`, which the router invokes via
`safeTransferFrom(path[0], msg.sender, pair, amountIn)` — i.e. *before* the router reads reserves in
`_swapSupportingFeeOnTransferTokens`. So the ordering within a user's sell is:

1. Router pulls the user's tokens → `FLOKI._transfer` → `beforeTransferHandler`.
2. The treasury sells up to 3% of the pool's reserve, draining ETH from the pool.
3. Control returns; the user's tokens are credited to the pair.
4. The router computes the user's output **against the now-depleted ETH reserve**.

The user receives materially less ETH than the quote their front-end computed one block earlier —
roughly the treasury's own price impact, ~2.9% at `priceImpactBasisPoints = 300`.

**Impact:** any user who sets a sane slippage tolerance (0.5–1%) has their transaction **revert**,
paying gas for nothing, whenever the treasury has accumulated tokens. The practical workaround users
discover is to raise slippage to 6%+ — which then makes them profitable sandwich targets. The
mechanism pushes the entire user base into a posture that maximises MEV extraction against them.

**Fix:** the same restructuring recommended in [C-01](#c-01): move treasury processing out of the
transfer hook into a keeper-called `processTreasury()`, or at minimum gate it behind
`minimumSwapThreshold` and a per-block cooldown so it fires rarely rather than on every sell:

```solidity
uint256 public lastProcessedBlock;

// ... inside beforeTransferHandler, after the pool checks:
if (block.number == lastProcessedBlock) {
    return;
}
lastProcessedBlock = block.number;
```

---

<a id="m-03"></a>
## M-03 — MEDIUM — `StaticTaxHandler` constructor has no upper bound

**Location:** `contracts/tax/StaticTaxHandler.sol:34-36`

```solidity
constructor(uint256 initialTaxBasisPoints) {
    taxBasisPoints = initialTaxBasisPoints;    // unbounded
}
```

`setTaxBasisPoints` enforces a strictly-decreasing ratchet, which is a genuinely good design — but
it only constrains the *path*, never the *starting point*. Deploying with `10000` gives a permanent
100% tax that the ratchet then locks in as the ceiling. Deploying with anything **above** `10000`
makes `getTax` return more than `amount`, so `FLOKI._transfer` line 448 underflows and **every
taxed transfer reverts** — a total sell freeze, from a constructor argument.

**Fix:**

```solidity
/// @notice Absolute ceiling on the tax, in basis points.
uint256 public constant MAX_TAX_BASIS_POINTS = 1000; // 10%

constructor(uint256 initialTaxBasisPoints) {
    require(
        initialTaxBasisPoints <= MAX_TAX_BASIS_POINTS,
        "StaticTaxHandler:constructor:TAX_TOO_HIGH: Initial tax exceeds the permitted maximum."
    );
    taxBasisPoints = initialTaxBasisPoints;
}
```

---

<a id="m-04"></a>
## M-04 — MEDIUM — `addExchangePool` can designate an ordinary wallet, enabling targeted taxation

**Location:** `contracts/utils/ExchangePoolProcessor.sol:42-46`

`addExchangePool` accepts any address with no validation that it is a Uniswap pair (no
`IUniswapV2Pair.factory()` probe, no `token0`/`token1` check). Adding a regular holder's wallet
means:

- Every transfer **to** that wallet is taxed at the sell rate — an owner-controlled, per-address levy
  with no dedicated event and no `isTaxed(address)` view for holders to check.
- Under `ExponentialTaxHandler`, every transfer **from** that wallet is taxed as a "buy" (line 66).
- Under `TreasuryHandlerAlpha`, every transfer to that wallet triggers a treasury swap (line 87).

This is a soft blacklist: it does not block the victim, it just makes anyone who pays them lose 3%
(or up to 81%). Combined with the absence of exemption transparency ([M-05](#m-05)), holders cannot
audit who is affected.

**Fix:**

```solidity
function addExchangePool(address exchangePool) external onlyOwner {
    require(exchangePool != address(0), "ExchangePoolProcessor:addExchangePool:ZERO_ADDRESS");
    require(
        exchangePool.code.length > 0,
        "ExchangePoolProcessor:addExchangePool:NOT_A_CONTRACT: Pools must be contracts."
    );

    if (_exchangePools.add(exchangePool)) {
        emit ExchangePoolAdded(exchangePool);
    }
}
```

A `code.length` check is a weak but cheap guard; validating `IUniswapV2Pair(exchangePool).factory()`
against the router's factory is stronger where the pool type is known. Also note that
`removeExchangePool` does not clear `primaryPool` if the removed pool *is* the primary pool, leaving
`primaryPool` pointing at an unregistered address:

```solidity
function removeExchangePool(address exchangePool) external onlyOwner {
    if (_exchangePools.remove(exchangePool)) {
        if (primaryPool == exchangePool) {
            emit PrimaryPoolUpdated(primaryPool, address(0));
            primaryPool = address(0);
        }
        emit ExchangePoolRemoved(exchangePool);
    }
}
```

(Be aware that clearing `primaryPool` interacts with [C-03](#c-03) and [H-05](#h-05) — apply those
fixes first, or removing a pool becomes its own sell freeze.)

---

<a id="m-05"></a>
## M-05 — MEDIUM — Tax exemptions are not externally readable

**Location:** `contracts/tax/StaticTaxHandler.sol:20`, `contracts/tax/ExponentialTaxHandler.sol:21`

```solidity
EnumerableSet.AddressSet private _exempted;
```

The set is `private` with no accessor. `ExchangePoolProcessor` exposes `getExchangePoolAddresses()`
for pools, but there is no equivalent for exemptions. The `TaxExemptionUpdated` event lets an indexer
reconstruct the set from logs, but no contract or explorer read can answer "is this address exempt?"
directly.

**Impact:** holders cannot verify whether insiders are exempt from the tax they themselves pay —
a core disclosure for any tax token, and the fact that exemption is invisible while the tax is
visible is itself a red flag for third-party analysers.

**Fix:**

```solidity
/**
 * @notice Determine whether the given address is exempt from taxation.
 * @param account Address to check.
 * @return True if the address is exempt, else false.
 */
function isExempt(address account) external view returns (bool) {
    return _exempted.contains(account);
}

/**
 * @notice Get the full list of tax-exempted addresses.
 * @return An array of exempted addresses.
 */
function getExemptions() external view returns (address[] memory) {
    return _exempted.values();
}
```

---

<a id="m-07"></a>
## M-07 — MEDIUM — `renounceOwnership` can permanently brick a misconfigured deployment

**Location:** all `Ownable` contracts — `Floki.sol:15`, `ExchangePoolProcessor.sol:11`,
`TreasuryHandlerAlpha.sol:18`

Renouncing ownership is frequently done to signal decentralisation. Here it is a trap: several of
this system's states are only escapable by an owner call.

- Renounce while `primaryPool` is unset or `priceImpactBasisPoints == 0` → **all sells revert
  forever** ([C-03](#c-03)).
- Renounce while `treasury` cannot receive ETH → **all sells revert forever** ([H-03](#h-03)).
- Renounce with `ExponentialTaxHandler` installed and `primaryPool` unset → **permanent 81% sell
  tax** ([H-05](#h-05)).
- Renounce after any router migration or pool change → the treasury's tokens are stranded, and
  `withdraw()` explicitly refuses to release them (line 210-213).

**Fix:** block renunciation until the system is demonstrably functional, and adopt two-step
ownership transfer:

```solidity
import "@openzeppelin/contracts/access/Ownable2Step.sol";  // OZ >= 4.7

function renounceOwnership() public view override onlyOwner {
    revert("TreasuryHandlerAlpha:renounceOwnership:DISABLED: Ownership cannot be renounced.");
}
```

`Ownable2Step` also addresses the single-step `transferOwnership` risk noted in [L-07](#l-07) —
note it requires bumping `@openzeppelin/contracts` from `^4.3.2` to `^4.7.0`.

---

# 4. Lower-severity findings

<a id="l-01"></a>
### L-01 — `require(amount > 0)` violates ERC-20 and breaks integrations
**`Floki.sol:442`** — EIP-20 states that transfers of 0 values MUST be treated as normal transfers
and fire the `Transfer` event. Reverting breaks aggregators, vesting contracts, and payment splitters
that legitimately settle zero amounts. It is also the mechanism by which [C-03](#c-03) escalates from
a no-op into a protocol-wide sell freeze.

```solidity
require(from != address(0), "FLOKI:_transfer:FROM_ZERO: Cannot transfer from the zero address.");
require(to != address(0), "FLOKI:_transfer:TO_ZERO: Cannot transfer to the zero address.");
require(amount <= _balances[from], "FLOKI:_transfer:INSUFFICIENT_BALANCE: Transfer amount exceeds balance.");

// EIP-20 requires zero-value transfers to succeed and emit an event.
if (amount == 0) {
    emit Transfer(from, to, 0);
    return;
}
```

<a id="l-02"></a>
### L-02 — `ITaxHandler.getTax` is `view`, structurally preventing stateful tax logic
**`ITaxHandler.sol:16-20`** — no implementation of this interface can ever maintain per-address
volume counters, cooldowns, launch-window ramps, or cumulative anti-whale windows. This is the root
cause of [M-01](#m-01) and a permanent ceiling on what any future handler can express. Removing
`view` costs gas on every taxed transfer but is the only way to unlock that class of logic; decide
deliberately rather than by omission.

<a id="l-03"></a>
### L-03 — `afterTransferHandler` burns ~5,000 gas per transfer to do nothing
**`TreasuryHandlerAlpha.sol:143-154`** — the function body is empty, but `nonReentrant` performs two
`SSTORE`s on `_status` (1→2, 2→1) on **every single FLOKI transfer**, plus the external call
overhead. Since the body has no state to protect, drop the modifier; better, have `FLOKI._transfer`
skip the call entirely when the handler declares no post-transfer work.

<a id="l-04"></a>
### L-04 — Residual router allowance after `_addLiquidity`
**`TreasuryHandlerAlpha.sol:244`** — `token.approve(address(router), tokenAmount)` grants the full
amount, but `addLiquidityETH` consumes only the reserve-optimal quantity and the remainder stays
approved indefinitely. Reset to zero after the call (shown in the [H-01](#h-01) fix).

<a id="l-05"></a>
### L-05 — Liquidity ETH split over-allocates relative to the documented formula
**`TreasuryHandlerAlpha.sol:113-122`** — the ASCII diagram documents `L = (B/2) × (P/10000)` for
tokens, but the ETH side uses the *undivided* `weiEarned × P/10000`. For `liquidityBasisPoints =
2000` the ETH allocated is ~2.2× what the token side can pair with. No funds are lost — the router
refunds surplus ETH and line 130-133 sweeps it to the treasury — but the code does not do what its
comment says, and the discrepancy would become a real loss if the refund behaviour ever changed
(e.g. a router migration). Correct form:

```solidity
// ETH is allocated in proportion to the tokens that were actually sold, so that the pairing
// ratio matches the diagram above.
uint256 weiForLiquidity = (weiEarned * tokensForLiquidity) / tokensForSwap;
```

<a id="l-06"></a>
### L-06 — Tokens sent to the token contract itself are permanently lost
**`Floki.sol:441`** — `to` is checked against `address(0)` but not against `address(this)`. FLOKI has
no rescue function, so misdirected tokens are unrecoverable while still counting toward
`totalSupply()` ([S-01](#1-supply-manipulation--unauthorized-inflation)).

```solidity
require(to != address(this), "FLOKI:_transfer:SELF_TRANSFER: Cannot transfer to the token contract.");
```

<a id="l-07"></a>
### L-07 — Assorted hardening
- **Single-step `transferOwnership`** on all four `Ownable` contracts — a typo'd address permanently
  loses admin control over a system with several owner-only escape hatches. Use `Ownable2Step`
  ([M-07](#m-07)).
- **`IERC20Metadata` not implemented** — `name`/`symbol`/`decimals` exist but the interface is not
  declared, so ERC-165-style consumers and some indexers will not detect them. `name()` is `public`
  while `symbol()`/`decimals()` are `external`; make them consistent.
- **`ecrecover` malleability** in `delegateBySig` (`Floki.sol:251`) — the upper-range `s` variant of
  any signature is also accepted. **Not exploitable here**, because `nonces[signatory]++` (line 255)
  consumes the nonce and prevents replay. Still, using OpenZeppelin's `ECDSA.recover`, which rejects
  malleable signatures and handles the `address(0)` case, is the conventional hardening.
- **Event ordering in `_transfer`** — the tax `Transfer` (line 459) is emitted before the principal
  `Transfer` (line 464), and `afterTransferHandler` runs between them. Indexers that assume the main
  transfer event precedes its fee event will mis-attribute. Emit the principal transfer first.
- **`LenientReentrancyGuard` silently returns** (`:38-40`) rather than reverting. This is
  intentional and correctly enables the nested router call, but it means a reentrant
  `beforeTransferHandler` provides no signal at all. Emitting an event on the silent-return path
  would make the behaviour observable without changing semantics.

---

# 5. Recommended remediation order

| Priority | Action | Findings addressed |
|----------|--------|--------------------|
| 1 | Add `onlyToken` to both treasury hooks | [C-01](#c-01) |
| 2 | Add `MAX_TAX_BASIS_POINTS` enforcement inside `FLOKI._transfer` | [C-02](#c-02), [M-03](#m-03), [H-05](#h-05) |
| 3 | Early-return on zero/dust swap amounts; floor `priceImpactBasisPoints` | [C-03](#c-03) |
| 4 | Replace `amountOutMin = 0` with a TWAP-anchored bound, or move swapping to a keeper function | [C-01](#c-01), [H-01](#h-01), [M-02](#m-02) |
| 5 | Reorder `transferFrom` to check-then-transfer | [H-02](#h-02) |
| 6 | Make the ETH sweep non-reverting; fix `withdraw` to `safeTransfer` | [H-03](#h-03), [H-04](#h-04) |
| 7 | Fail open on unset `primaryPool` in `ExponentialTaxHandler`; add rate setters | [H-05](#h-05) |
| 8 | Timelock `setTaxHandler` / `setTreasuryHandler` / `setTreasury`; disable renunciation; move ownership to a multisig | [C-02](#c-02), [M-07](#m-07) |
| 9 | Complete the deploy script (exemptions, pools, primary pool, ownership handover) | [M-06](#m-06), [C-03](#c-03), [H-05](#h-05) |
| 10 | Transparency and hygiene: `isExempt`, zero-value transfers, dead code removal | [M-05](#m-05), [L-01](#l-01), [H-05](#h-05) |

## Invariants worth asserting in tests

The `test/` directory currently contains only `types.ts` — there are no test cases at all. At
minimum, the following should be property-tested (Foundry invariant tests or Hardhat fuzzing):

1. `Σ balances == totalSupply()` after any sequence of transfers. *(Currently holds — protects the
   supply guarantees in section 1.)*
2. `votes[R] == Σ balances[a] where delegates[a] == R`, for every `R`, after any sequence of
   transfers and delegations. *(Currently holds.)*
3. For any transfer, `tax <= amount * MAX_TAX_BASIS_POINTS / 10000`. *(Currently violated — any
   handler may return up to `amount`.)*
4. A non-owner holding tokens can always sell a non-dust amount into a funded pool. *(Currently
   violated by [C-03](#c-03), [H-03](#h-03), [C-02](#c-02).)*
5. No externally-owned account other than the token contract can cause `token.balanceOf(treasuryHandler)`
   to decrease. *(Currently violated by [C-01](#c-01).)*
