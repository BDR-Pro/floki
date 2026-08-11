# FLOKI Token — Escalation Chain Analysis

**Companion to:** [`TOKENOMIC_SECURITY_AUDIT.md`](./TOKENOMIC_SECURITY_AUDIT.md)
**Commit:** `bbfd130`
**Question addressed:** which Low/Medium findings compose into High/Critical exploits?

---

## Method, and what this document is not

Individually-rated findings are scored in isolation. Real exploits rarely respect that boundary — a
"Low" spec deviation is often the *mechanism* that converts a benign rounding condition into a
protocol-wide freeze, and two "Mediums" that each look like hygiene can combine into an unbounded
loss.

This document re-examines every Low and Medium finding from the main report and asks: **is there a
reachable chain in which this contributes to High or Critical impact?** Where the answer is yes, the
finding is re-rated **on the merits of the demonstrated chain**, with the preconditions, the attacker
capability required, and the code path stated explicitly so each claim can be checked.

Where the answer is no, the finding stays where it is. **Five findings could not be escalated and are
listed in [§8](#8-findings-that-could-not-be-escalated) with the reason each attack fails.** That
section is the control: escalations are only worth anything if the analysis was capable of returning
"no."

This pass also surfaced **one new Critical** (X-01) that neither the individual findings nor my
proposed fixes for them covered, and produced **one correction to a fix I recommended in the main
report** ([§7](#7-correction-to-a-recommendation-in-the-main-report)).

### Re-rating summary

| Chain | Components | Original | Escalated | Attacker capability required |
|-------|-----------|----------|-----------|------------------------------|
| [X-01](#x-01) | L-01 + C-03 root cause + H-04 | Low / Critical | **Critical** *(new vector)* | Anyone. Dust + gas. |
| [X-02](#x-02) | H-03 + L-07 (lenient guard) | High / Low | **Critical** | Whoever controls `treasury` |
| [X-03](#x-03) | M-01 + H-01 | Medium / High | **Critical** | Anyone with trading capital |
| [X-04](#x-04) | M-04 + M-05 + C-03 | Medium / Medium | **Critical** | Owner, then any designated wallet |
| [X-05](#x-05) | M-02 + L-01 | Medium / Low | **High** | None — occurs organically |
| [X-06](#x-06) | M-06 + M-05 | Medium / Medium | **High** | None — occurs organically |
| [X-07](#x-07) | M-07 as amplifier | Medium | **Critical amplifier** | Owner, one call |

---

<a id="x-01"></a>
## X-01 — CRITICAL (new) — Anyone can permanently freeze all sells by sending dust to the treasury handler

**Components:** L-01 (zero/dust amounts are fatal) + C-03's root cause (no minimum swap threshold) +
H-04 (`withdraw` refuses to release the token)
**Attacker capability: none. Cost: a dust transfer plus gas.**

This is the most severe finding in either document, and it is not any one of the three components on
its own. Each was rated Low or scoped to owner error. Together they form a permissionless, permanent
denial of service on the entire sell path.

### The chain

**Step 1 — anyone can put the treasury handler into a dust state.** `token.balanceOf(treasuryHandler)`
is just a balance. Any address can `transfer(treasuryHandlerAddress, 3)`. This is a plain
wallet-to-wallet transfer: untaxed, unrestricted, and indistinguishable from a mistake.

**Step 2 — a dust balance makes `beforeTransferHandler` revert.** With `contractTokenBalance == 3`
and the deploy-script `liquidityBasisPoints = 2000`:

```solidity
if (contractTokenBalance > 0) {                                  // 3 > 0 — passes
    // ... cap does not bind, 3 is far below 3% of the pool
    uint256 tokensForLiquidity = (3 * 2000) / 20000;             // = 0
    uint256 tokensForSwap = 3 - 0;                               // = 3
    _swapTokensForEth(3);                                        // <-- reverts
```

`_swapTokensForEth(3)` reaches `UniswapV2Pair.swap` with an input of 3 base units. Against any
realistically-sized pool, `getAmountOut(3, reserveIn, reserveOut)` truncates to **0** in integer
arithmetic, and the pair enforces:

```solidity
require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');
```

The revert propagates: `pair.swap` → `router` → `_swapTokensForEth` → `beforeTransferHandler` →
`FLOKI._transfer` → the user's `transferFrom` → **the user's sell fails.**

**Step 3 — it applies to every seller, forever.** The condition is a property of the treasury
handler's balance, not of the transaction. Every subsequent sell by every holder takes the same path
and reverts identically. Buys are untouched (line 87-89 returns early when the beneficiary is not a
pool), and wallet-to-wallet transfers are untouched. **Buys work, sells revert — a textbook honeypot,
armed by an anonymous third party for the cost of dust.**

**Step 4 — the state is not clearable.** Every exit is closed:

| Recovery attempt | Result |
|---|---|
| `withdraw(address(token), 3)` | Blocked — `require(tokenAddress != address(token))` (H-04, line 210-213) |
| Sell the dust | Reverts — that is the bug |
| Lower `priceImpactBasisPoints` | Worse — clamps `contractTokenBalance` to 0, which reverts on FLOKI's own `require(amount > 0)` |
| Raise `liquidityBasisPoints` to 10000 | `tokensForLiquidity = 1`, `tokensForSwap = 2` — still rounds to zero output, still reverts |
| Send *more* tokens to escape the dust range | Works, but requires someone to notice and donate real value, and the attacker can re-dust at any time |
| `FLOKI.setTreasuryHandler(newHandler)` | **The only reliable fix** — owner-only, and abandons all accumulated tax |

And if ownership has been renounced ([X-07](#x-07)), even the last row is gone: **permanent, total,
irreversible sell freeze.**

### Why the fixes in the main report do not stop this

This is the important part, and it is why the chain analysis was worth doing.

- The `onlyToken` modifier from C-01 does **not** help — the revert happens on the legitimate,
  token-initiated path.
- The `if (amountToProcess == 0) return;` guard I proposed for C-03 does **not** help —
  `amountToProcess` is 3, not 0. The zero-check is on the wrong quantity.
- `minimumSwapThreshold` as I wrote it **defaults to 0** and I never set it in the constructor, so a
  deployment applying my patch verbatim remains fully vulnerable.

### Corrected fix

Three defences, all needed:

```solidity
/// @notice Minimum accumulated balance before a swap is attempted. Must be large enough that the
/// AMM cannot round the output to zero.
uint256 public minimumSwapThreshold;

constructor(
    address treasuryAddress,
    address tokenAddress,
    address routerAddress,
    uint256 initialLiquidityBasisPoints,
    uint256 initialPriceImpactBasisPoints,
    uint256 initialMinimumSwapThreshold
) {
    require(
        initialMinimumSwapThreshold > 0,
        "TreasuryHandlerAlpha:constructor:ZERO_THRESHOLD: Threshold must be non-zero."
    );
    ...
    minimumSwapThreshold = initialMinimumSwapThreshold;
}

function setMinimumSwapThreshold(uint256 newThreshold) external onlyOwner {
    require(newThreshold > 0, "TreasuryHandlerAlpha:setMinimumSwapThreshold:ZERO_THRESHOLD");
    minimumSwapThreshold = newThreshold;
}
```

**Defence 2 — the swap must never be able to revert the user's transfer.** A threshold bounds the
known case; it cannot bound the unknown ones (router migration, pool desync, a paused pair). Treasury
processing is an optimisation, not a correctness requirement, so it must fail soft:

```solidity
function beforeTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external override onlyToken nonReentrant {
    benefactor;
    amount;

    if (!_exchangePools.contains(beneficiary) || primaryPool == address(0)) {
        return;
    }

    uint256 contractTokenBalance = token.balanceOf(address(this));
    uint256 maxPriceImpactSale = (token.balanceOf(primaryPool) * priceImpactBasisPoints) / 10000;
    uint256 amountToProcess = contractTokenBalance < maxPriceImpactSale
        ? contractTokenBalance
        : maxPriceImpactSale;

    if (amountToProcess < minimumSwapThreshold) {
        return;
    }

    // Treasury processing must never be able to block a holder from transacting. If the router
    // reverts for any reason, skip this round and try again on the next sell.
    try this.processTreasury(amountToProcess) {} catch {
        emit TreasuryProcessingSkipped(amountToProcess);
    }
}

/// @dev External only so that it can be wrapped in `try`/`catch` above. Self-call only.
function processTreasury(uint256 amountToProcess) external {
    require(msg.sender == address(this), "TreasuryHandlerAlpha:processTreasury:UNAUTHORIZED");
    ...
}
```

**Defence 3 — make the token recoverable.** H-04's blanket ban is what makes step 4 terminal. Allow
the accumulated token to be withdrawn, but only above the amount currently owed to the treasury
process — or simply allow it and rely on the timelocked owner:

```solidity
function withdraw(address tokenAddress, uint256 amount) external onlyOwner {
    if (tokenAddress == address(0)) {
        treasury.sendValue(amount);
    } else {
        // The accumulating token is withdrawable too: refusing to release it converts any
        // stuck-balance condition into a permanent protocol freeze (see X-01).
        IERC20(tokenAddress).safeTransfer(treasury, amount);
    }
}
```

---

<a id="x-02"></a>
## X-02 — CRITICAL — The treasury address holds an unbounded reentrancy window and a guaranteed pre-trade callback on every sell

**Components:** H-03 (owner-settable `treasury`, reverting receive freezes sells) + L-07 (the lenient
guard returns silently)
**Original ratings: High + Low. Escalated: Critical.**

H-03 was scoped as "a treasury that *cannot* receive ETH freezes sells." That framing understates it
by a wide margin. The real issue is what a treasury that *can* receive ETH is handed on every trade.

### The mechanism

```solidity
// TreasuryHandlerAlpha.sol:130-133 — inside the nonReentrant body
uint256 remainingWeiBalance = address(this).balance;
if (remainingWeiBalance > 0) {
    treasury.sendValue(remainingWeiBalance);
}
```

`Address.sendValue` is:

```solidity
(bool success, ) = recipient.call{value: amount}("");
```

A bare `call` with **no gas stipend** — the full remaining gas is forwarded. So if `treasury` is a
contract, its `receive()` executes arbitrary code at a very specific and very valuable moment:

1. **Inside `beforeTransferHandler`**, which is
2. **inside `FLOKI._transfer`**, which is
3. **inside the router's `safeTransferFrom` of the user's tokens**, which happens
4. **before the router reads reserves to price the user's swap.**

Three consequences follow, none of which is visible from the treasury's role description.

**(a) Guaranteed, riskless, uncontested front-run on every sell.** The treasury contract is invoked
with full knowledge of an in-flight sell, before that sell's output price is determined. It can sell
its own holdings first and let the user absorb the impact. This is not probabilistic MEV won in a gas
auction — it is a reserved slot in the middle of every trade, available to exactly one address.

**(b) A reentrancy window in which treasury processing is silently disabled.** At the moment of the
callback, `_status == _ENTERED`. `LenientReentrancyGuard` *returns silently* rather than reverting
(`LenientReentrancyGuard.sol:38-40`) — the L-07 item. So any transfer the treasury makes from inside
its own callback skips `beforeTransferHandler` and `afterTransferHandler` entirely, with no revert
and no event. `FLOKI._transfer` has no reentrancy guard of its own, so the token core offers no
backstop. The lenient guard is *necessary* for the legitimate nested router call, which is why it
exists — but it means the silent-skip behaviour extends to a caller nobody intended to grant it to.

**(c) The freeze in H-03 is the benign case.** A reverting `receive()` is loud and immediately
diagnosable. A `receive()` that quietly extracts value on every trade is not.

### Why the escalation is justified

H-03 alone reads as "don't set a bad treasury address." The chain shows that the *contract shape* of
the treasury is a protocol-level security parameter that the code neither documents nor constrains,
and `setTreasury` (`:192-202`) validates only that the address is non-zero. Combined with C-02's
missing timelock, an owner can install this in one transaction, and combined with M-05's opacity
there is no view function anywhere that would let a holder notice.

### Fix

Sever the callback entirely. The treasury must be a passive recipient, and its behaviour must never
be able to affect a transfer:

```solidity
uint256 remainingWeiBalance = address(this).balance;
if (remainingWeiBalance > 0) {
    // Gas-capped and non-reverting on purpose. The treasury is a recipient, not a participant:
    // it must not be able to run logic during a user's trade, and it must not be able to block
    // one. Unsent ETH stays here and is swept on the next successful sell.
    (bool succeeded, ) = treasury.call{ value: remainingWeiBalance, gas: 2300 }("");
    succeeded;
}
```

A 2300-gas stipend permits an EOA and a plain `receive() {}` and nothing else. If the treasury must
be a contract that does real work on receipt, invert the flow to a pull model — accrue
`withdrawableByTreasury` and let the treasury call `claim()` in its own transaction, outside any
user's trade.

---

<a id="x-03"></a>
## X-03 — CRITICAL — The split-sell bypass turns treasury extraction into a loop that survives the C-01 fix

**Components:** M-01 (tiers are per-transaction, bypassable by splitting) + H-01 (`amountOutMin = 0`)
**Original ratings: Medium + High. Escalated: Critical.**

M-01 was rated Medium as a *tax fairness* problem: whales split sells to pay 3% instead of 81%. The
escalation is that splitting is simultaneously a **treasury extraction primitive**, and — critically
— it is the reason the headline fix for C-01 is insufficient.

### The chain

Each sub-sell independently triggers `beforeTransferHandler`. The guard does not prevent this:
`LenientReentrancyGuard` resets `_status` to `_NOT_ENTERED` at the end of each completed hook, and
the sub-sells are **sequential, not nested**. N sub-sells in one transaction therefore produce N
separate treasury swaps, each with `amountOutMin = 0`, at N prices the attacker controls because the
attacker's own sub-sells are what move the price between them.

One transaction:

```
for i in 1..N:
    sell chunk_i into the pool          // depresses price; also triggers...
    └─ beforeTransferHandler fires      // ...a treasury dump at the now-depressed price, 0 min out
buy back the full position at the end
```

The attacker's opening sells and closing buy-back approximately cancel, less two 0.3% LP fees. The
treasury's dumps are pure loss: sold into the depressed segment of the curve with no price floor. The
forfeited value is split between the attacker's round trip and passive LPs — the attacker captures a
substantial share rather than all of it, but **the treasury's loss is total either way**, and the
attacker's cost is bounded at roughly 0.6% of the capital they cycled.

### Why this is the important part

**The `onlyToken` access-control fix for C-01 does not stop this attack.** Every hook invocation here
is legitimate: the token really is calling the handler, on a real transfer, from a real sell. C-01's
fix closes the *unsolicited* trigger; X-03 shows the trigger was never the necessary ingredient.
`amountOutMin = 0` was.

That reorders the remediation priority in the main report. Item 1 (`onlyToken`) is necessary but does
not close the extraction vector; **item 4 (a TWAP-anchored slippage bound, or moving swaps out of the
transfer hook) is the load-bearing fix**, and X-03 is the proof.

### Fix

The `minimumSwapThreshold` from [X-01](#x-01) plus the per-block cooldown from M-02 blunt the loop by
collapsing N dumps into one:

```solidity
uint256 public lastProcessedBlock;

// ... after the pool and threshold checks:
if (block.number == lastProcessedBlock) {
    return;
}
lastProcessedBlock = block.number;
```

That caps the attack at one dump per block instead of N per transaction, which removes the atomicity
the attacker depends on. It does **not** remove the underlying zero-slippage exposure — only a TWAP
bound or a keeper-supplied `amountOutMin` does that.

---

<a id="x-04"></a>
## X-04 — CRITICAL — `primaryPool` is an unvalidated, manipulable oracle; designating a wallet hands a non-owner the freeze switch

**Components:** M-04 (`addExchangePool` accepts any address) + M-05 (no exemption/designation
transparency) + C-03's dependency on `balanceOf(primaryPool)`
**Original ratings: Medium + Medium. Escalated: Critical.**

M-04 was rated Medium as "targeted taxation." The escalation is that `primaryPool` is not merely a
tax flag — **it is read as a price oracle by two safety-critical calculations**, and `addExchangePool`
performs no validation that the address is a pool at all.

```solidity
// ExponentialTaxHandler.sol:70 — sets everyone's tax tier
uint256 priceImpactBasisPoint = token.balanceOf(primaryPool) / 10000;

// TreasuryHandlerAlpha.sol:93-94 — sets the sell cap, and the sell-freeze condition
uint256 primaryPoolBalance = token.balanceOf(primaryPool);
uint256 maxPriceImpactSale = (primaryPoolBalance * priceImpactBasisPoints) / 10000;
```

`setPrimaryPool` (`ExchangePoolProcessor.sol:64-78`) requires only that the address is in
`_exchangePools` — a set that `addExchangePool` populates with **no check that the entry is a
contract, let alone a Uniswap pair**.

### The chain

An owner adds an ordinary EOA to `_exchangePools` and calls `setPrimaryPool` on it. `balanceOf` of
that address is now a number an ordinary wallet holder changes by sending a transaction. That number
controls:

1. **Everyone's sell tax.** Empty the wallet → `priceImpactBasisPoint == 0` → all three tier
   comparisons in `ExponentialTaxHandler` collapse to `amount <= 0` → **every sell is taxed at 81%**
   (H-05's failure mode, now triggerable by a non-owner at will).
2. **Whether selling is possible at all.** The same empty wallet gives `maxPriceImpactSale == 0` →
   `contractTokenBalance` clamps to 0 → `_swapTokensForEth(0)` → FLOKI's `require(amount > 0)` →
   **every sell reverts** (C-03, now triggerable by a non-owner at will).

So a single owner misconfiguration — one that looks like routine pool registration — **delegates a
global 81%-tax switch and a global sell-freeze switch to whoever holds that wallet.** Neither switch
is visible: M-05 means there is no `isExempt`, there is no `isTaxed`, and while
`getExchangePoolAddresses()` and `primaryPool` are public, nothing signals that the primary pool is
an EOA rather than a pair.

### The latent version, with a real pool

Even correctly configured, both call sites read **spot reserves**, which are manipulable within a
transaction. This is the standard spot-price-as-oracle flaw. I want to be precise about which
directions are actually profitable, because not all of them are:

- **Inflating the cap** (donating tokens to the pair before triggering a dump) is *not* profitable
  as a standalone: the router's fee-on-transfer swap path computes `amountInput` as
  `balanceOf(pair) - reserveInput`, so the donation is consumed as swap input and the resulting ETH
  goes to the treasury handler. The attacker subsidises the treasury.
- **Griefing a victim into the 81% tier** by draining the pool's token reserve requires removing
  ~85% of it, which costs more than the tax extracted. Not economical.
- **Tax evasion** via tier manipulation is real but redundant — [X-03](#x-03)'s splitting achieves the
  same 3% rate for free.

The defensible statement is therefore: with a legitimate pool, spot-reserve dependence is a **latent
design flaw** that constrains what can safely be built on it; with M-04's missing validation, it is
an **immediately Critical** delegation of protocol control.

### Fix

Validate pool registration, and derive tier boundaries from a manipulation-resistant source:

```solidity
function addExchangePool(address exchangePool) external onlyOwner {
    require(exchangePool != address(0), "ExchangePoolProcessor:addExchangePool:ZERO_ADDRESS");
    require(
        exchangePool.code.length > 0,
        "ExchangePoolProcessor:addExchangePool:NOT_A_CONTRACT: Pools must be contracts."
    );
    // Stronger, where the pool type is known: confirm the address really is a pair from the
    // expected factory, so that `primaryPool` cannot be pointed at an attacker-controlled balance.
    require(
        IUniswapV2Pair(exchangePool).factory() == expectedFactory,
        "ExchangePoolProcessor:addExchangePool:UNKNOWN_FACTORY"
    );

    if (_exchangePools.add(exchangePool)) {
        emit ExchangePoolAdded(exchangePool);
    }
}
```

Combine with the fail-open guard from H-05 (`poolBasisPoint == 0` returns the *base* rate, never the
top tier) and the `primaryPool == address(0)` early return from [X-01](#x-01), so that neither
consequence is reachable even if a bad designation slips through.

---

<a id="x-05"></a>
## X-05 — HIGH — Honest, slippage-protected sells revert systematically

**Components:** M-02 (treasury front-runs the user's own sell) + L-01 (dust/zero amounts are fatal)
**Original ratings: Medium + Low. Escalated: High.**

M-02 was written up as a UX problem. Reframed against who it actually affects, it is a functional
availability failure for the majority of holders.

The treasury's dump executes inside the user's `transferFrom`, *before* the router prices the user's
swap, and moves up to `priceImpactBasisPoints` of the pool — ~2.9% of the ETH reserve at the shipped
setting. So the price a front-end quoted one block earlier is systematically unattainable.

The consequence is a sorting effect on holders:

| User's slippage setting | Outcome |
|---|---|
| 0.5% – 1% (front-end defaults) | **Transaction reverts.** Gas spent, no sale. Repeats indefinitely while the treasury holds tokens. |
| ~6%+ (what users adopt after repeated failures) | Sale succeeds — and the user is now a profitable sandwich target for the entire market |

There is no setting that is both safe and functional. The protocol pushes its whole user base into
the posture that maximises MEV extraction against them, and the users who behave most cautiously are
the ones who cannot transact at all. Rated High on availability: a majority of holders cannot execute
a basic sell under default tooling, and the remedy the system teaches them makes them worse off.

L-01 contributes the sharp edge — when the treasury's balance is in the dust range the transfer does
not merely underdeliver, it reverts unconditionally ([X-01](#x-01)).

**Fix:** the per-block cooldown and `minimumSwapThreshold` from [X-01](#x-01)/[X-03](#x-03) reduce the
frequency of the interference. Eliminating it requires moving treasury processing out of the transfer
path entirely — a keeper-called `processTreasury()` never collides with a user's quote.

---

<a id="x-06"></a>
## X-06 — HIGH — The liquidity ETH leak is silent, unobservable, and indefinite

**Components:** M-06 (treasury handler not tax-exempt) + M-05 (exemptions not externally readable)
**Original ratings: Medium + Medium. Escalated: High.**

M-06 established the leak: with the treasury handler not exempt, its `transferFrom` into the pair
during `_addLiquidity` is taxed, the pair receives less than `amountToken` while the full `amountETH`
is deposited, `UniswapV2Pair.mint` mints against the short token side, and the surplus ETH is donated
to existing LPs.

M-05 is what escalates it. There is no `isExempt(address)` and no `getExemptions()` on either tax
handler — `_exempted` is `private` with no accessor. So:

- Nobody can query whether the exemption is in place. Confirming it requires replaying
  `TaxExemptionUpdated` logs from deployment, which no holder and no explorer does by default.
- The leak produces no error, no failed transaction, and no anomalous event. `_addLiquidity`
  succeeds; the LP tokens arrive at the treasury; only the *amount* is quietly short.
- The deploy script (`scripts/deploy-floki.ts:33-47`) never calls `addExemption`, so the default
  deployment state **is** the leaking state.

Escalated to High on the combination of *certainty* (it is the shipped default, not a hypothetical),
*duration* (indefinite — nothing surfaces it), and *cumulative magnitude* (a fixed percentage of the
ETH side of every liquidity addition, compounding for the life of the protocol). A one-off 3% error is
Medium; a permanent, undetectable 3% skim on all liquidity operations is not.

**Fix:** the exemption calls in the deploy script from M-06, plus the `isExempt`/`getExemptions`
accessors from M-05 — the latter is what makes the former verifiable. Add a deployment-time assertion:

```typescript
// Fail the deployment loudly rather than leaking quietly for the life of the protocol.
if (!(await exponentialTaxHandler.isExempt(treasuryHandlerAlpha.address))) {
  throw new Error("Treasury handler must be tax-exempt before the pool goes live");
}
```

---

<a id="x-07"></a>
## X-07 — CRITICAL AMPLIFIER — `renounceOwnership` converts every recoverable state above into a permanent one

**Component:** M-07
**Original rating: Medium. Escalated: Critical amplifier.**

M-07 is not an exploit; it is a multiplier, and it belongs at the top of the severity table because of
what it multiplies. Renouncing ownership is routinely done to signal decentralisation and is
frequently *demanded* by communities as a trust signal — which is exactly what makes it dangerous
here.

Every Critical in both documents has an owner-only escape hatch, and only an owner-only escape hatch:

| Failure state | Sole recovery | After renunciation |
|---|---|---|
| [X-01](#x-01) dust freeze | `FLOKI.setTreasuryHandler` | **Permanent total sell freeze** |
| [X-04](#x-04) wallet as `primaryPool` | `setPrimaryPool` / `removeExchangePool` | **Permanent 81% tax or permanent freeze** |
| C-03 unset `primaryPool` | `setPrimaryPool` | **Permanent total sell freeze** |
| H-03 / [X-02](#x-02) bad treasury | `setTreasury` | **Permanent total sell freeze** |
| H-05 81% tier fallthrough | `FLOKI.setTaxHandler` | **Permanent 81% sell tax** |
| Router migration / dead pool | `setTreasuryHandler` | **Treasury tokens stranded forever** (H-04) |

Note the interaction with C-02's remediation: adding a **timelock** to the handler setters is correct,
but a timelock plus renunciation is strictly worse than either alone — the delay window exists and
then the ability to use it is destroyed. Sequence matters: move ownership to a timelocked multisig,
and never renounce.

**Fix:** disable renunciation outright on every contract in the system.

```solidity
/// @dev Ownership cannot be renounced: several recoverable misconfigurations in this system are
/// only escapable through an owner call, and renouncing would make them permanent. Transfer
/// ownership to a timelock instead.
function renounceOwnership() public view override onlyOwner {
    revert("renounceOwnership:DISABLED: Transfer ownership to a timelock instead.");
}
```

---

<a id="7-correction-to-a-recommendation-in-the-main-report"></a>
## 7. Correction to a recommendation in the main report

**In the main report (L-02, and the M-01 fix) I recommended removing `view` from
`ITaxHandler.getTax` to enable stateful anti-whale logic. Do not apply that change as written — it
would open a reentrancy hole.**

A `view` external call compiles to `STATICCALL`, which the EVM enforces: the callee cannot write
storage, emit events, send value, or reenter destructively. That means the current interface gives
the token a real, if accidental, safety property — **a malicious tax handler installed via C-02 is
confined to returning a bad number.** It cannot execute a reentrant callback inside `_transfer`, and
`_transfer` is precisely where reentrancy would be most damaging: `getTax` is called at line 447,
*before* any balance is updated at lines 450-455.

Removing `view` converts that `STATICCALL` into a `CALL` and hands every tax handler a reentrancy
window at the worst possible point in the transfer. Since `FLOKI._transfer` has no reentrancy guard
of its own, and `transferFrom` validates the allowance only *after* `_transfer` returns
([H-02](./TOKENOMIC_SECURITY_AUDIT.md#h-02)), that window is directly chainable into an
allowance-drain.

If stateful tax logic is genuinely wanted, the interface change must be paired with **both** a
`nonReentrant` guard on `FLOKI._transfer` **and** the H-02 reordering, and the resulting reentrancy
surface re-reviewed as a unit. Otherwise, keep `view` and accept that per-transaction tiers are
bypassable ([X-03](#x-03)) — which, given that X-03 shows the tiers are economically ineffective
anyway, is the better trade.

---

<a id="8-findings-that-could-not-be-escalated"></a>
## 8. Findings that could not be escalated

These stay where they are. Each was tested against a specific attack hypothesis that failed, and the
reason is recorded so the conclusion can be rechecked if the code changes.

**L-04 — residual router allowance — stays Low.**
Hypothesis: the leftover `token.approve(router, tokenAmount)` after `_addLiquidity` lets a third party
pull tokens from the treasury handler. **Fails.** Every value-moving entry point on
`UniswapV2Router02` sources tokens via `TransferHelper.safeTransferFrom(token, msg.sender, ...)` —
the router pulls from its own caller, never from an arbitrary `from` address. The allowance is
`treasuryHandler → router` and is only usable when `msg.sender == treasuryHandler`. Worth clearing as
hygiene; not exploitable.

**L-05 — liquidity ETH over-allocation — stays Low.**
Hypothesis: the mismatch between the documented `B/2 × P/10000` token formula and the undivided
`weiEarned × P/10000` ETH allocation leaks ETH, or reverts on insufficient balance. **Fails on both.**
`weiForLiquidity ≤ weiEarned` for all `liquidityBasisPoints ≤ 10000`, so the balance is always
sufficient; and `addLiquidityETH` refunds `msg.value - amountETH`, with line 130-133 sweeping the
refund to the treasury. Real code/comment divergence, no loss today — but it becomes a live loss if
the router is ever swapped for one that does not refund, which is why it should still be corrected.

**L-03 — `afterTransferHandler` gas waste — stays Low.**
Hypothesis: the two `SSTORE`s on `_status` per transfer enable a griefing DoS. **Fails.** ~5,000 gas
on every transfer is a real and pointless cost, but it is far below any block-limit or
economic-denial threshold. Pure inefficiency.

**L-06 — tokens sent to `address(this)` are lost — stays Low.**
Hypothesis: chains with [X-01](#x-01) into a freeze. **Fails.** The token contract's own balance is
never read by any code path — `_transfer` does not consult it, and no handler references it. Stranded
value and a `totalSupply()` accuracy problem, nothing more.

**L-07 (ecrecover malleability) — stays Low.**
Hypothesis: the upper-range `s` variant permits a replay of `delegateBySig`. **Fails.**
`nonces[signatory]++` at `Floki.sol:255` consumes the nonce, so the malleable twin of a signature is
rejected on the second use. Worth switching to OpenZeppelin's `ECDSA.recover` as hardening; not
exploitable.

*(The other L-07 sub-items — single-step `transferOwnership`, missing `IERC20Metadata`, event
ordering — are unchanged. The lenient-guard sub-item was escalated as a component of
[X-02](#x-02).)*

---

## 9. Revised remediation order

The chains above reorder the main report's priority list. Two changes matter most: **X-01 is now
first**, and **the zero-slippage fix moves ahead of the access-control fix**, because [X-03](#x-03)
demonstrates that `onlyToken` alone leaves the extraction vector fully open.

| Priority | Action | Closes |
|---|---|---|
| 1 | Non-zero `minimumSwapThreshold` + `try`/`catch` around treasury processing + allow token withdrawal | [X-01](#x-01), [X-05](#x-05), C-03 |
| 2 | TWAP-anchored `amountOutMin`, or move swapping to a keeper-called function with caller-supplied bounds | [X-03](#x-03), C-01, H-01, [X-05](#x-05) |
| 3 | Gas-cap and de-revert the treasury ETH send; or convert to a pull model | [X-02](#x-02), H-03 |
| 4 | `MAX_TAX_BASIS_POINTS` enforced inside `FLOKI._transfer` | C-02, H-05, M-03 |
| 5 | `onlyToken` on both treasury hooks | C-01 (unsolicited trigger only) |
| 6 | Validate `addExchangePool`; fail *open* on `poolBasisPoint == 0` | [X-04](#x-04), H-05 |
| 7 | Disable `renounceOwnership`; move ownership to a timelocked multisig | [X-07](#x-07), C-02 |
| 8 | Reorder `transferFrom` to check-then-transfer | H-02 |
| 9 | `isExempt`/`getExemptions`; complete the deploy script; assert exemptions at deploy time | [X-06](#x-06), M-05, M-06 |
| 10 | Keep `getTax` as `view` unless items 8 and a `_transfer` guard land together — see [§7](#7-correction-to-a-recommendation-in-the-main-report) | L-02 |

### Additional invariants for the test suite

Extending the list in the main report — `test/` still contains only `types.ts`:

6. Sending an arbitrary dust amount to the treasury handler does not prevent any holder from selling.
   *(Currently violated — [X-01](#x-01).)*
7. No sequence of external calls can cause `beforeTransferHandler` to revert. *(Currently violated —
   [X-01](#x-01), [X-04](#x-04), H-03.)*
8. The `treasury` address cannot observe or act within a user's transfer. *(Currently violated —
   [X-02](#x-02).)*
9. N split sells of size `S` cost the treasury no more than one sell of size `N×S`. *(Currently
   violated — [X-03](#x-03).)*
10. `balanceOf(primaryPool)` is a contract balance belonging to a pair from the expected factory.
    *(Currently unenforced — [X-04](#x-04).)*
