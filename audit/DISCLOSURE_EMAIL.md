**To:** legal@floki.com
**Cc:** security@floki.com
**Subject:** Responsible security disclosure — permissionless treasury drainage & sell-freeze in FLOKI token contracts

---

Hello FLOKI team,

I am writing to responsibly disclose two security vulnerabilities I identified in the FLOKI token
smart-contract system (`Floki.sol` and the `TreasuryHandlerAlpha` / `ExponentialTaxHandler`
satellite contracts). I am reporting this in good faith so it can be remediated before it is
exploited, and I have not shared these details with anyone else.

I have **not** attempted, and will not attempt, to exploit these issues against any live deployment or
user funds. All of my analysis was performed against the published source code and reproduced in a
local, self-contained simulation. This message is a disclosure, not a demand — I am not requesting
payment as a condition of this report, and the timeline and any bounty are entirely at your discretion
under your program's terms.

**Summary of findings**

1. **Permissionless treasury drainage (Critical).** `TreasuryHandlerAlpha.beforeTransferHandler` has
   no caller restriction and executes a Uniswap sale of the treasury's accumulated tax tokens with
   the minimum output set to zero (`amountOutMin = 0`). Any account can force the treasury to
   liquidate its balance at a price the caller controls and capture the difference in a single atomic
   transaction, at effectively zero net capital (inventory can be flash-borrowed). No privileged role
   is required, and no short position or price bet is involved — it is direct value extraction.

2. **Permissionless sell freeze / honeypot (High, conditional on pool liquidity).** By leaving a
   precisely-sized dust balance in the treasury handler, a routed swap rounds to zero output and
   reverts, which propagates into every holder's sell while buys continue to succeed. The contract's
   `withdraw` function cannot clear the condition. This is exploitable in thin-liquidity / low-price
   conditions (for example, around launch).

I have also documented several related issues, including unbounded owner-swappable tax/treasury
handlers that could impose a 100% sell tax, which I have separated out as they concern privileged
roles rather than external attackers.

**What I can provide**

- A full written report with root-cause analysis, exploit walkthrough, economic impact, and
  recommended fixes with corrected code.
- A runnable proof-of-concept (Python, standard library only) that reproduces both findings
  deterministically, including an honest negative control showing the freeze does not trigger on a
  deep pool.
- Assistance validating the fixes, and, if useful, help porting the PoC to an on-chain fork test.

**How to proceed**

Could you please confirm:
- the best secure channel to send the technical report and proof-of-concept (for example, an
  encrypted email address or a PGP key), and
- whether these contracts fall under a formal bug-bounty or vulnerability-disclosure program, and its
  scope and terms.

I am happy to follow any coordinated-disclosure process you prefer and to agree on a reasonable
remediation window before any public write-up. My aim is simply to see this fixed safely.

Thank you for your time, and for building openly enough that this review was possible.

Best regards,
[Your name]
[Optional: contact details / PGP fingerprint / GitHub handle]

---

*Notes before you send this (delete before sending):*
- *Verify the recipient address and whether FLOKI publishes a dedicated `security@` or a bounty
  program (e.g. on Immunefi); prefer their official channel over `legal@` if one exists, and use any
  published PGP key.*
- *Do not attach the full exploit details or PoC to this first email — wait for a secure channel and
  written acknowledgement, so working exploit code is not sitting in an unencrypted inbox.*
- *Fill in your name/handle. Keep a timestamped copy of this message and any replies for your records.*
- *Confirm the deployed contract matches the reviewed source before claiming impact on live funds.*
