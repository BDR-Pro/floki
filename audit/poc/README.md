# FLOKI PoC — `floki_poc.py`

A **faithful, executable simulation** of the FLOKI token's on-chain logic that reproduces two
permissionless vulnerabilities deterministically, using only the Python standard library.

```bash
python3 floki_poc.py
```

No dependencies, no network, no fork required.

---

## What it is (and is not)

**It is** a line-faithful port of the relevant contract logic — `FLOKI._transfer` (including the
`require(amount > 0)` and the pre-transfer treasury hook ordering), `ExponentialTaxHandler.getTax`
(the buy/sell tax tiers), `TreasuryHandlerAlpha.beforeTransferHandler` (the unauthenticated hook, the
3% cap, the `amountOutMin = 0` swap), and `UniswapV2Library.getAmountOut` / `Pair.swap` (integer
math, 0.3% fee, the `INSUFFICIENT_OUTPUT_AMOUNT` revert). The integer arithmetic matches Solidity, so
the "swap output rounds to zero" behaviour and the tax-tier boundaries are genuine, not asserted.

**It is not** an on-chain transaction. It does not deploy bytecode or execute against a fork. It
proves the *economics and control flow* of the bugs; for a program that requires an on-chain PoC,
port these exact steps to a Foundry mainnet-fork test (see "Elevating to a fork test" below).

> The simulated magnitudes below **supersede the idealised hand-calculation** in
> `../ATTACK_CHAIN_DEEPDIVE.md §4` (which reported ~31% treasury loss). The honest, reproducible
> figures are 10–13% treasury loss / 5–10 ETH attacker profit for the tested configuration; the
> attack is real, permissionless, and ETH-neutral, and the magnitude scales with pool and treasury
> size.

---

## What it proves

### Finding 1 — permissionless, floor-less treasury drainage
Any account, with **zero net ETH** (inventory flash-borrowed), forces the treasury to liquidate its
tax balance at a price the attacker sets. The PoC runs the full sequence — split sells to stay in the
3% tax tier while walking the price down, unauthenticated `beforeTransferHandler` triggers to force
tranches out at `amountOutMin = 0`, then an ETH-neutral buy-back — and asserts:

- the treasury realises **less** than an honest single sale would have;
- the attacker ends **ETH-neutral** (`|Δ ETH| ≤ 1 wei`);
- the attacker ends with a **FLOKI surplus** (the value the treasury lost).

Representative output (pool 500B FLOKI / 500 ETH, treasury bag = 20% of pool):

```
  Finding 1  non-exempt attacker : treasury loses 8.50 ETH (10%), attacker profit ~5.27 ETH
  Finding 1  exempt attacker     : treasury loses 10.62 ETH (13%), attacker profit ~10.11 ETH
```

The attack repeats every time the treasury re-accumulates tax.

### Finding 2 — permanent sell freeze via computed dust
The PoC **computes** the largest dust amount whose swap output floors to zero at the live reserves
(this is *not* a fixed "3 wei" — it depends on the reserve ratio), leaves that dust in the treasury
handler, and shows every holder's sell then reverts while buys still succeed:

```
  computed dust size  : 100 base unit(s)  (getAmountOut(100) == 0 wei)
  holder sell         : REVERTED -> UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT
  holder buy          : SUCCEEDED -> received 83,124,895,781 FLOKI
```

**Honest negative control:** the script also runs a deep/high-price pool where `getAmountOut` never
rounds to zero, and correctly reports the freeze does **not** trigger there. The freeze is an
exploitable risk in **thin-liquidity / low-price** conditions (launch, low-cap) and requires the
treasury to be near-empty first — a state Finding 1 (or any ordinary sell that clears the treasury)
produces naturally.

---

## Preconditions (both faithful to a real deployment)

- Token live, pools registered, `primaryPool` set, `ExponentialTaxHandler` + `TreasuryHandlerAlpha`
  installed — the end-state of `scripts/deploy-floki.ts`.
- Finding 1: treasury holds accumulated tax (accrues from ordinary trading; larger bag → larger theft).
- Finding 2: treasury near-empty and a reserve ratio where dust rounds to zero (thin/low-price pool).

None of these is a misconfiguration.

---

## Elevating to a Foundry fork test (for programs requiring an on-chain PoC)

1. `forge test --fork-url $RPC` against the chain where FLOKI is deployed.
2. Bind the deployed `FLOKI`, `TreasuryHandlerAlpha`, `ExponentialTaxHandler`, and the Uniswap pair.
3. Replace the simulation's `sell`/`buy`/`force_treasury_dump` with real router calls and a direct
   `treasuryHandler.beforeTransferHandler(address(0), pool, 0)`; fund the attacker via a Uniswap V2
   flash swap or Aave flash loan for the inventory leg.
4. Assert the same invariants: treasury token balance falls, attacker ETH is net-neutral with a FLOKI
   surplus (Finding 1); a third-party sell reverts while a buy succeeds (Finding 2).

The control flow is identical to this file; only the call layer changes.

---

## Files

- `floki_poc.py` — the runnable PoC (this directory).
- `../../bug_report.md` — the bounty-submission report.
- `../ATTACK_CHAIN_DEEPDIVE.md` — the EVM-level attack trace and remediation.
