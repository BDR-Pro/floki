# FLOKI Token — Full Chain-of-Attack Report (Deep Dive)

**Companions:** [`TOKENOMIC_SECURITY_AUDIT.md`](./TOKENOMIC_SECURITY_AUDIT.md) ·
[`ESCALATION_CHAINS.md`](./ESCALATION_CHAINS.md) · [`KILL_CHAIN.md`](./KILL_CHAIN.md)
**Commit:** `bbfd130` · **Compiler:** `0.8.11`

This report reconstructs the complete treasury-drainage attack at the level of the EVM call trace,
with a worked numeric example, the exact economic bounds, capital structuring, and the interaction
with the anti-whale tax. It **corrects a simplification** in `KILL_CHAIN.md`: because the treasury
hook is a *pre-transfer* hook, the naive "sell → trigger → buy" sandwich does not extract cleanly on
the first tranche, and the anti-whale tax forces the attacker into split sells. The refined mechanism
is stronger and more precise, and it makes clear *why* the attack's magnitude scales with the
treasury's accumulated balance.

> **Verification basis.** Every FLOKI/handler line reference is checked against this repo. Router and
> pair internals are reasoned from the canonical UniswapV2 source (`node_modules` not installed).
> Numbers in the worked example are illustrative — they use round reserves and omit the 0.3% LP fee
> in the core AMM steps (accounted for separately in "Costs") — but the arithmetic is exact for the
> stated inputs and conserves the constant product at every step.

---

## 0. TL;DR

A single account with **no privileges** and **no net ETH capital** (inventory can be flash-borrowed)
can force the FLOKI treasury to liquidate its entire accumulated tax balance into the AMM at a price
the attacker sets, with **no slippage floor**, and pocket the difference. The larger the treasury's
balance relative to the per-trigger cap, the larger the theft. After extraction the same account can
**permanently freeze every holder's ability to sell** for the cost of a 3-unit dust transfer.

The chain composes six findings that were individually rated from Low to Critical:

```
  C-01  ──►  H-01  ──►  M-01  ──►  M-02  ──►  drainage  ──►  X-01
  no-auth    no price   split      pre-price   treasury       dust
  hook       floor      sells      hook        emptied        permafreeze
             (min=0)    (2 roles)              at bad prices   (L-01+H-04)
```

The single most valuable fix is **H-01** (a real slippage floor); it neutralises the money hops
regardless of the others. The intuitive fix — access control on the hook (C-01) — does *not* stop
the attack.

---

## 1. Actors, preconditions, assumptions

| | |
|---|---|
| **Attacker** | Any EOA. No owner role, no allowance, no whitelist. Runs a contract to bundle calls atomically. |
| **Net capital** | ≈ zero. Needs transient FLOKI inventory for the price-move legs, which is flash-loanable; strategy is ETH-neutral. |
| **Precondition 1** | Token live, `primaryPool` set, pools registered, `ExponentialTaxHandler` + `TreasuryHandlerAlpha` installed — i.e. the exact end-state of `scripts/deploy-floki.ts`. |
| **Precondition 2** | The treasury handler holds accumulated tax FLOKI. This accrues automatically from ordinary trading; the attacker can also manufacture it by generating taxed volume. |
| **Precondition 3 (for large extraction)** | Treasury balance `T` exceeds the per-trigger cap `= priceImpactBasisPoints/10000 × poolReserve` (3% at deploy default). When `T` is below the cap, the chain degrades to griefing + a small back-run (§5.4). |

**None of these is a misconfiguration.** The attack targets the intended, documented deployment.

---

## 2. How a sell actually flows (the substrate the attack rides on)

Before the attack, fix the exact ordering, because the whole exploit turns on it. When any account
sells FLOKI through the router, this is the call tree:

```
user ─► Router.swapExactTokensForETHSupportingFeeOnTransferTokens(amountIn, amountOutMin, [FLOKI,WETH], to, deadline)
         │
         ├─(1)─► TransferHelper.safeTransferFrom(FLOKI, user, pair, amountIn)
         │         └─► FLOKI.transferFrom(user, pair, amountIn)
         │               └─► FLOKI._transfer(user, pair, amountIn)                         [Floki.sol:435]
         │                     ├─(a)─► treasuryHandler.beforeTransferHandler(user, pair, …) [Floki.sol:445]  ◄── TREASURY DUMPS HERE
         │                     │         └─► (if pair is a pool) sell up to cap for ETH, amountOutMin = 0
         │                     ├─(b)─► tax = taxHandler.getTax(user, pair, amountIn)         [Floki.sol:447]
         │                     ├─(c)─► _balances update: user-=amountIn; pair+=amountIn-tax  [Floki.sol:450]
         │                     └─(d)─► treasuryHandler.afterTransferHandler(…)  (no-op)      [Floki.sol:462]
         │
         └─(2)─► _swapSupportingFeeOnTransferTokens([FLOKI,WETH], to)
                   ├─ amountInput = FLOKI.balanceOf(pair) - reserveInput   ◄── user's swap priced AFTER the dump
                   └─ pair.swap(...) → ETH to `user`
```

**The load-bearing fact (finding M-02):** step (a) — the treasury's own market sell — executes
*before* step (2), where the seller's trade is priced. So the treasury dump is fully baked into the
reserves that the triggering sell then trades against. The treasury front-runs every seller,
including the attacker. This ordering is what breaks the naive sandwich and dictates the correct
attack structure below.

Two corollaries the attacker exploits:

- **Buys never trigger a dump.** For a buy, `beneficiary` is the buyer, not a pool, so
  `beforeTransferHandler` returns at line 87-89. Only sells (transfers *to* a pool) dump the treasury.
- **The dump on the very first sell prices at the pre-sell reserves.** So the first tranche the
  treasury sells is at (approximately) fair value; the loss grows on later tranches once the attacker
  has moved the price.

---

## 3. The chain, hop by hop (EVM-level)

### HOP 0 — Reconnaissance (public reads, no bug)

```solidity
address   pool      = handler.primaryPool();               // ExchangePoolProcessor.sol:18
uint256   impactBps = treasury.priceImpactBasisPoints();   // 300 at deploy default
uint256   T         = token.balanceOf(address(treasury));  // the prize
(uint112 rF, uint112 rE,) = IUniswapV2Pair(pool).getReserves();
```

The attacker now knows the pool, the per-trigger cap `= impactBps/10000 × rF`, the treasury bag `T`,
and the reserves. If `T` spans several caps, the payoff is large; the attacker sizes the attack from
these numbers.

### HOP 1 — Permissionless trigger — **C-01** (`TreasuryHandlerAlpha.sol:77`)

```solidity
function beforeTransferHandler(address benefactor, address beneficiary, uint256 amount)
    external nonReentrant                       // ← no onlyToken, no auth whatsoever
{
    benefactor; amount;                          // ignored (lines 83-84)
    if (!_exchangePools.contains(beneficiary)) return;   // only gate: beneficiary must be a known pool
    ...                                          // ← proceeds to market-sell the treasury bag
}
```

`treasury.beforeTransferHandler(address(0), pool, 0)` forces a dump on demand — **without any
accompanying transfer.** This decouples "make the treasury sell" from "sell your own tokens," which
is the capability the attacker needs to place dumps *after* they have moved the price. → the dump
runs a router swap, and that swap has no floor.

### HOP 2 — No slippage floor — **H-01** (`TreasuryHandlerAlpha.sol:226-235`)

```solidity
router.swapExactTokensForETHSupportingFeeOnTransferTokens(
    tokenAmount,
    0,              // ← amountOutMin: accept ANY ETH, including dust
    path, address(this), block.timestamp
);
```

Whatever price the pool is at when this line runs, the treasury takes it. Combined with HOP 1's
timing control, the attacker chooses that price. → but the attacker cannot move the price with one
large sell, because of the tax.

### HOP 3 — Split sells: tax evasion *and* dump multiplier — **M-01** (`ExponentialTaxHandler.sol:70-80`)

Here is the subtlety that `KILL_CHAIN.md` glossed. If the attacker tries to depress the price with
one big sell, the anti-whale tax annihilates it:

```solidity
uint256 priceImpactBasisPoint = token.balanceOf(primaryPool) / 10000;   // = rF / 10000
if      (amount <= priceImpactBasisPoint *  300) return (amount *  300) / 10000; // ≤3% of pool → 3%
else if (amount <= priceImpactBasisPoint * 1000) return (amount *  900) / 10000; // ≤10%        → 9%
else if (amount <= priceImpactBasisPoint * 2000) return (amount * 2700) / 10000; // ≤20%        → 27%
else                                             return (amount * 8100) / 10000; // >20%        → 81%
```

A single sell large enough to move the price sits in the 27% or **81%** tier — the attacker would
forfeit most of their inventory. So the attacker **splits** the front-run into sub-sells each
`≤ 3% of the pool`, staying in the 3% tier. M-01 (rated Medium purely as a fairness bug) now serves
**two** roles for the attacker at once:

1. **Tax minimisation** — keeps every front-run leg in the 3% bracket instead of 81%.
2. **Dump multiplication** — each sub-sell independently re-enters `beforeTransferHandler` (the
   lenient guard resets between *sequential* calls, `LenientReentrancyGuard.sol:37-48`), forcing a
   fresh treasury tranche out at the progressively-depressed price.

→ the interleaving of "sub-sell depresses" and "hook dumps" is the engine. HOP 2's `min = 0` means
each tranche after the first is sold into the depression for almost nothing.

### HOP 4 — Drainage (the composed effect)

Putting HOPs 1-3 together, the attacker's contract, in one transaction:

```
for each sub-sell chunk c (c ≤ 3% of current pool):        // stay in 3% tax tier
    router.sell(c)                                          // (i) hook dumps a tranche, then (ii) c lands → price ↓
until price is deep enough and/or treasury nearly empty
for k extra triggers:                                      // mop up remaining bag at the floor
    treasury.beforeTransferHandler(0, pool, 0)             // each dumps ≤ cap of current pool, min = 0
buy back all FLOKI with the ETH raised                     // ETH-neutral; keep the surplus FLOKI
```

The treasury's first tranche leaves at ~fair value (pre-price hook, §2); every subsequent tranche
leaves at the depressed price the attacker built. Worked numbers in §4.

### HOP 5 — Permanent sell freeze — **X-01 = L-01 + no-threshold + H-04**

After exiting, the attacker locks the token so no holder can follow:

```solidity
token.transfer(address(treasury), 3);   // 3 base units. Untaxed wallet transfer. ~21k gas.
```

Now every seller's transfer re-enters `beforeTransferHandler` with `contractTokenBalance == 3`, which
passes `> 0` (line 92, the L-01 trap door), computes `tokensForSwap = 3`, and calls
`_swapTokensForEth(3)`. `getAmountOut(3, hugeReserve, hugeReserve)` truncates to **0**, so
`pair.swap` reverts `INSUFFICIENT_OUTPUT_AMOUNT`, and the revert propagates up into **every seller's
`transferFrom`.** Buys and wallet transfers still work — a honeypot. `withdraw` cannot clear it
(H-04 forbids withdrawing the token, line 210-213), so only `FLOKI.setTreasuryHandler` (owner) can
recover — nothing, if ownership was renounced (X-07). Full analysis in
[`ESCALATION_CHAINS.md#x-01`](./ESCALATION_CHAINS.md#x-01).

---

## 4. Worked economic example

**Pool:** `rF = 1,000,000` FLOKI, `rE = 1,000` ETH → spot `0.001` ETH/FLOKI, `k = 1e9`.
**Per-trigger cap:** `3% × rF = 30,000` FLOKI (recomputed against the live reserve each trigger).
**Treasury bag:** `T = 200,000` FLOKI (20% of the pool — spans ~6 caps).
**Attacker:** treats the swaps as fee-less here (LP fee handled in §6); assumed tax-exempt for the
core AMM math, with the tax drag added back in §6.

The attacker depresses the price with split sells and forces the bag out in tranches. Tracing the
treasury's realised ETH per tranche as the pool walks down:

| Step | Action | Tranche sold | Pool after (FLOKI ; ETH) | Treasury ETH received |
|-----:|--------|-------------:|--------------------------|----------------------:|
| 0 | dump @ fair (pre-price, first sell) | 30,000 | 1,030,000 ; 970.87 | **29.13** |
| 1 | attacker depresses to here via split sells | — | 1,330,000 ; 751.88 | — |
| 2 | forced trigger | 39,900 | 1,369,900 ; 730.00 | **21.88** |
| 3 | forced trigger | 41,097 | 1,410,997 ; 708.72 | **21.28** |
| 4 | forced trigger | 42,330 | 1,453,327 ; 688.08 | **20.64** |
| 5 | forced trigger | 43,600 | 1,496,927 ; 668.04 | **20.04** |
| 6 | forced trigger (bag exhausted) | 3,073 | 1,500,000 ; 666.67 | **1.37** |

**Treasury total: 114.34 ETH** for its entire 200,000-FLOKI bag.

Benchmark: an *honest* single sale of 200,000 FLOKI into the untouched pool yields
`1000 − 1e9/1,200,000 = 166.67 ETH`. So the forced, fragmented, floor-less liquidation costs the
treasury **≈ 52 ETH (~31%) versus an honest sale**, and ~86 ETH versus naive spot value.

**Where the 52 ETH goes — the attacker's back-run.** The attacker sold 300,000 FLOKI on the way down
(the "depress" legs) for ~218.99 ETH, then buys back with that same 218.99 ETH at the depressed
price:

```
buy-back out = 1,500,000 − 1e9/(666.67 + 218.99) = 370,900 FLOKI
```

The attacker recovers **370,900 FLOKI for the 300,000 they sold** — surplus **+70,900 FLOKI**, ETH
neutral. At the post-trade price that surplus is worth **≈ 55 ETH.** The treasury's loss has landed,
almost entirely, in the attacker's wallet; LPs net roughly flat (made whole by the fees omitted
here).

**Conservation check (fee-less):** across all actors the pool's constant product `k = 1e9` is
preserved at every row above, treasury ETH out (114.34 vs the 166.67 it would have earned) reconciles
with the attacker's surplus (~55 ETH) plus the difference retained by the depressed pool state. The
arithmetic closes.

---

## 5. Attack variants

### 5.1 Atomic, flash-funded (capital ≈ 0)
Wrap HOPs 1-4 in a Uniswap V2 flash swap (or Aave/Balancer flash loan) of the FLOKI inventory used
for the depress legs. The strategy is ETH-neutral and self-financing: borrow FLOKI → run the loop →
buy back → repay FLOKI → keep the surplus. True at-risk capital is the flash fee plus gas.

### 5.2 Organic-sell sandwich (does not even need C-01)
The treasury dumps on *any* sell. A mempool bot that spots a large pending organic sell can sandwich
the combined (victim sell + forced treasury tranche), exploiting `amountOutMin = 0` on the treasury's
portion, in a standard cross-transaction sandwich. C-01 only adds the ability to *manufacture* the
trigger when no organic sell is pending — convenient, not required. **This is why the C-01 access-
control fix alone does not close the vector.**

### 5.3 Slow griefing (no capital, no inventory)
Call `beforeTransferHandler(0, pool, 0)` once per block. Each call forces the treasury to eat one LP
fee (0.3%) plus its own price impact, and hands the resulting slippage to any back-runner. Over time
this bleeds the treasury with zero attacker capital and no manipulation — pure denial of value.

### 5.4 Small-bag degradation
When `T <` cap, one sell dumps the whole bag at ~fair price and there is no depressed tranche to
skim; the attacker gets only the §5.3 griefing value plus a small back-run of the treasury's own
impact. The attack's payoff is therefore **monotonic in the treasury's accumulated balance** — it
pays to wait for the bag to grow, and the protocol has no mechanism that caps how large it gets.

### 5.5 Owner-side express lane (one transaction, total loss)
Orthogonal but worth stating in a chain report: via **C-02** the owner swaps in a malicious tax
handler returning `tax == amount` on sells — an instant 100%-sell honeypot while the owner exits at
0% — or `amount + 1` for an invisible freeze. No multi-hop needed; a single Critical. Shares HOP 5's
sealing move and the renounce-to-permanence amplifier (X-07). Defeated by the `MAX_TAX_BASIS_POINTS`
ceiling enforced inside `FLOKI._transfer`.

---

## 6. Costs, and net profitability under the tax

The §4 figure assumes an exempt attacker. For a non-exempt attacker on the shipped
`ExponentialTaxHandler`:

| Cost component | Magnitude (on the §4 example) |
|---|---|
| Sell tax on depress legs (kept in 3% tier via M-01 split) | 3% × ~219 ETH cycled ≈ **6.6 ETH** |
| Buy tax on the back-run (flat 3% on buys, line 66-67) | 3% × ~219 ETH ≈ **6.6 ETH** |
| LP fees, ~0.3% per swap over ~10-15 swaps | **~1–2 ETH** |
| Flash-loan fee (if used), ~0.09% (Aave) on borrowed FLOKI | small |
| Gas (loop of ~10-15 swaps + triggers) | tens of USD on L1; negligible on L2 |
| **Gross extraction** | **≈ 55 ETH** |
| **Net profit (non-exempt attacker)** | **≈ 38–40 ETH** |

Two multipliers on the attacker's side:

- **Split sells cut the tax from 81% to 3%** — without M-01 the tax drag alone (81% on any
  price-moving sell) would make the attack unprofitable. M-01 is not a side-quest; it is what makes
  the economics work.
- **If the attacker is (or becomes) tax-exempt** — e.g. an exemption granted for a "market maker,"
  or via a compromised owner — the drag disappears and net ≈ gross ≈ 55 ETH. Because exemptions are
  not externally enumerable (**M-05**), holders cannot tell whether such an exemption exists.

Even at the non-exempt figure, the return on ≈ zero net capital is effectively unbounded, and it
repeats every time the treasury re-accumulates.

---

## 7. On-chain footprint & detection

- **The forced dump is nearly invisible.** `beforeTransferHandler` emits **no event of its own**; the
  only trace is the resulting Uniswap `Swap` from the treasury handler and a `Transfer` to the
  treasury EOA — indistinguishable from ordinary treasury operation. There is no `TreasurySold`
  event, no threshold log, nothing tying the swap to an external trigger.
- **The permafreeze is silent too.** `token.transfer(treasury, 3)` is an ordinary `Transfer(attacker,
  treasury, 3)` event. Nothing announces that sells are now bricked; holders discover it only when
  their own sells revert.
- **Monitoring that would have caught it:** (a) alert on `beforeTransferHandler` calls whose
  `msg.sender != address(token)` — impossible today because there is no such event and no restriction;
  (b) alert on treasury handler token balance falling into the dust range; (c) alert on the treasury
  handler receiving inbound `Transfer`s from non-router addresses. All three are only actionable
  *after* the fixes add the events.

---

## 8. Full remediation (sequenced by chain impact)

The ordering matters: **fix H-01 first** — it severs the money hops no matter who triggers them.
Then C-01 (removes forced timing and §5.1/§5.3), then X-01 (closes the freeze).

### 8.1 (H-01, HOPs 2-4) Give the treasury swap a real floor, and don't sell inside the transfer

A same-block `getAmountsOut` is **not** a fix — it reads the manipulated spot reserves. The floor
must come from outside the transaction (a TWAP) or from a caller who computed it off-chain. The
cleanest structural fix is to stop swapping inside the transfer hook entirely:

```solidity
// Accumulate in the hook; liquidate in a separate, access-controlled, slippage-bounded call.
uint256 public minimumSwapThreshold;          // non-zero; see 8.3

function beforeTransferHandler(address, address beneficiary, uint256) external override onlyToken nonReentrant {
    // Intentionally does NOT trade. The transfer path must be cheap and unsandwichable.
    if (_exchangePools.contains(beneficiary) && primaryPool != address(0)) {
        _pendingProcess = true;               // just a flag; keepers do the work
    }
}

/// @notice Liquidate accumulated tax. Caller supplies the slippage floor and deadline off-chain.
function processTreasury(uint256 amountOutMin, uint256 deadline) external onlyAuthorizedKeeper {
    uint256 bal = token.balanceOf(address(this));
    require(bal >= minimumSwapThreshold, "TreasuryHandlerAlpha:processTreasury:BELOW_THRESHOLD");

    uint256 cap = (token.balanceOf(primaryPool) * priceImpactBasisPoints) / 10000;
    uint256 toSell = bal < cap ? bal : cap;

    address[] memory path = new address[](2);
    path[0] = address(token); path[1] = router.WETH();
    token.approve(address(router), toSell);
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(toSell, amountOutMin, path, address(this), deadline);
    token.approve(address(router), 0);
    // ... liquidity + treasury send as before, also with real minimums
}
```

If keeping the in-hook swap is a hard requirement, the floor must be a Uniswap V2 cumulative-price
(TWAP) observation sampled at least one block old, and `deadline` must be a real caller-supplied
value, never `block.timestamp`.

### 8.2 (C-01, HOP 1 / §5.1 / §5.3) Restrict the hooks to the token

```solidity
modifier onlyToken() {
    require(msg.sender == address(token), "TreasuryHandlerAlpha:onlyToken:UNAUTHORIZED");
    _;
}
// applied to beforeTransferHandler and afterTransferHandler
```

Necessary but, per §5.2, **not sufficient** — it must ship together with 8.1.

### 8.3 (X-01 + C-03, HOP 5) Never hand the router a zero/dust amount; make the hook fail-soft; free the token

```solidity
constructor(..., uint256 initialMinimumSwapThreshold) {
    require(initialMinimumSwapThreshold > 0, "TreasuryHandlerAlpha:constructor:ZERO_THRESHOLD");
    minimumSwapThreshold = initialMinimumSwapThreshold;   // large enough that getAmountOut can't round to 0
    ...
}

// in whichever function performs the swap:
if (primaryPool == address(0) || toSell < minimumSwapThreshold) return;   // skip, never revert
try this.doSwap(toSell) {} catch { emit TreasuryProcessingSkipped(toSell); }   // treasury issues never brick transfers

// and stop bricking recovery:
function withdraw(address tokenAddress, uint256 amount) external onlyOwner {
    if (tokenAddress == address(0)) treasury.sendValue(amount);
    else IERC20(tokenAddress).safeTransfer(treasury, amount);   // token withdrawable; refusing it is what makes X-01 permanent
}
```

### 8.4 (M-01) Anti-whale must key on cumulative volume, not per-tx amount
Split sells defeat the per-transaction tiers. Track a per-address rolling window (requires removing
`view` from `ITaxHandler.getTax` **and** adding a `nonReentrant` guard on `FLOKI._transfer` plus the
H-02 reordering — see the correction in
[`ESCALATION_CHAINS.md#7`](./ESCALATION_CHAINS.md#7-correction-to-a-recommendation-in-the-main-report),
because making `getTax` stateful otherwise opens a reentrancy window inside `_transfer`).

### 8.5 (C-02) Cap every handler from inside the token
```solidity
uint256 public constant MAX_TAX_BASIS_POINTS = 1000; // 10%
// in _transfer, after computing tax:
require(tax <= (amount * MAX_TAX_BASIS_POINTS) / 10000, "FLOKI:_transfer:TAX_TOO_HIGH");
```
Plus timelock `setTaxHandler`/`setTreasuryHandler`/`setTreasury`, disable `renounceOwnership`, and
move ownership to a multisig. This neutralises §5.5 and the X-07 amplifier.

### 8.6 (M-05 / M-06) Transparency and deploy hygiene
Add `isExempt`/`getExemptions`; exempt the treasury handler in the deploy script and assert it
before go-live; add the `TreasurySold` / `TreasuryProcessingSkipped` events §7 relies on.

---

## 9. Fix-vs-chain matrix

| Fix | HOP 1 | HOP 2 | HOP 3 | HOP 4 | HOP 5 | §5.2 organic |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| 8.2 `onlyToken` (C-01) | ✅ | — | ✅ | ⚠️ weakened | — | ❌ still open |
| **8.1 slippage floor / keeper (H-01)** | — | ✅ | ✅ | ✅ **broken** | — | ✅ **broken** |
| 8.3 threshold + fail-soft + free token (X-01) | — | — | — | — | ✅ | — |
| 8.4 cumulative anti-whale (M-01) | — | — | ✅ | ⚠️ smaller | — | — |
| 8.5 tax ceiling + timelock (C-02) | — | — | — | — | — | — (kills §5.5) |

**Read the H-01 row:** it is the only fix that turns HOP 4 and the organic-sell variant from
"drained" to "broken." That is the whole argument for sequencing it first.

---

## 10. Invariants for the test suite (`test/` currently holds only `types.ts`)

1. No account other than `address(token)` can decrease `token.balanceOf(treasuryHandler)`. *(C-01)*
2. Any treasury liquidation realises ≥ `(1 − maxSlippageBps) ×` its TWAP-fair ETH value. *(H-01)*
3. `N` split sells of size `S` are taxed no less than one sell of size `N×S`. *(M-01)*
4. Sending arbitrary dust to the treasury handler never causes any holder's sell to revert. *(X-01)*
5. No sequence of external calls makes `beforeTransferHandler` revert the enclosing transfer. *(X-01/H-03)*
6. For every transfer, `tax ≤ amount × MAX_TAX_BASIS_POINTS / 10000`. *(C-02)*
7. `Σ balances == totalSupply()` and `votes[R] == Σ balances of R's delegators`, after any sequence.
   *(Currently hold — the supply/vote guarantees from the main report.)*

---

### Correction logged against `KILL_CHAIN.md`
That document's HOP 2-3 describes a "sell → trigger → buy" atomic sandwich as if the first forced
dump lands at the depressed price. Per §2 here, the treasury hook is a *pre-transfer* hook, so the
first tranche prices at ~fair value and the extraction is driven by the **later** tranches after the
attacker has walked the price down with tax-tier-limited split sells. The refined mechanism in this
report supersedes that sketch; the conclusion (permissionless, floor-less treasury drainage scaling
with the treasury balance, sealed by a dust freeze) is unchanged and, if anything, better supported.
