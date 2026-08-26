# BIP300/301 support in DATUM

Status: design. Nothing here is implemented yet.

This describes what it takes for a DATUM pool to vote on drivechain
governance and to carry blind-merged-mining commitments, in both directions:
the pool decides, the gateway builds, the chain records, and the pool reads the
result back.

## What has to end up in the coinbase

BIP300 governance and BIP301 merged mining are both expressed as OP_RETURN
outputs in the coinbase of a mainchain block. The enforcer knows how to build
them; the question is only how they reach the coinbase a miner is hashing.

| message | what it says | size |
|---|---|---|
| M1 | propose a sidechain | tag + number + description (**unbounded**) |
| M2 | ACK a sidechain proposal | tag + number + 32-byte hash ≈ 38 B |
| M3 | propose a withdrawal bundle | tag + number + 32-byte txid ≈ 38 B |
| M4 | ACK withdrawal bundles | tag + mode + 1–2 bytes per sidechain (**up to ~517 B**) |
| M7 | BMM accept — the h\* commitment | tag + 32 bytes ≈ 38 B |

M2, M3 and M7 are small. M1 and M4 are not, and that is the crux of the
protocol problem below.

## Why the gateway cannot do this today

Three separate blockers, each verified against the current code rather than
assumed.

### 1. The template's commitments are discarded

`datum_blocktemplates.c` parses exactly these fields from `getblocktemplate`:

    bits, coinbasevalue, curtime, data, default_witness_commitment, fee,
    hash, height, mintime, previousblockhash, sigoplimit, sigops, sizelimit,
    target, transactions, txid, version, weight, weightlimit

There is no `coinbasetxn` and no `coinbaseaux`. The gateway builds its coinbase
from scratch in `datum_coinbaser.c` out of the pool's payout list, its own
tags, and the witness commitment. Any BIP300 output the enforcer put in its
template is therefore dropped — silently, because nothing ever looked for it.

Pointing the gateway at the enforcer's template server instead of the node does
not fix this on its own. The commitments would still be parsed away.

### 2. The DATUM coinbaser caps a script at 64 bytes

`datum_coinbaser_v2_parse` reads a repeating record of

    [8 bytes value LE][1 byte script length][script]

and rejects the whole coinbaser if any `script length` is under 2 or over 64.
M2, M3 and M7 fit. **M1 and a wide M4 do not.** A pool that could only vote
when few sidechains existed would be a pool that stops voting exactly when
governance starts to matter.

The value field is fine as it stands: commitments are zero-value, and the
running tally against `coinbase_value` is unaffected by adding zero.

### 3. Commitments must not be trimmed away

The gateway fits the payout list to each worker's coinbase size limit, serving
older firmware a shorter list. That logic is right for payouts — a dropped
payout is deferred, not lost — but a dropped commitment is a vote that silently
did not happen, or a BMM commitment whose block earns nothing.

Commitments therefore need to be a different class of output: included first,
never trimmed, and counted against the size budget before any payout is
considered. If they do not fit, the correct behaviour is to serve a smaller
payout list, not a smaller vote.

### 4. The pool would reject its own blocks

`judgeOutputs` in BlockFabric verifies a share's coinbase pays only outputs the
pool offered that gateway, or the pool's own scripts. A BIP300 OP_RETURN is
neither, so every share carrying one would be rejected as an unauthorised
coinbase.

This check is load-bearing — it is what stops a gateway paying someone the pool
did not authorise — so the fix is not to relax it. Commitments have to become a
recognised third class: zero-value, provably an OP_RETURN carrying a known
BIP300 tag, and matched against what the pool itself sent for that job.

## Direction of travel

Two ways commitments could reach the coinbase. The difference matters because
of what DATUM is for.

**Via the enforcer's template.** The gateway takes `getblocktemplate` from the
enforcer rather than the node, and the enforcer injects commitments per its own
ACK policy. Simple, and wrong for this pool: it requires every miner to run an
enforcer, and it moves the governance decision to whoever runs the gateway.

**Via the DATUM protocol.** The pool computes the commitments — it already
holds the vote decisions — and sends them alongside the payout list it sends
every job. The gateway inserts what it is given. This keeps working for a miner
running their own node and their own gateway, which is the entire premise of
DATUM, and it keeps the governance decision with the pool that published it.

The second is the design. The first stays available as a degenerate case for an
operator running everything themselves.

## The bidirectional loop

    operator decides a vote
      → pool records it
      → pool asks the enforcer for the encoded outputs (GetCoinbasePSBT)
      → pool sends them to every gateway with the job's payout list
      → gateway puts them in the coinbase it builds
      → miner hashes it; a found block carries the vote
      → pool reads the outcome back from the enforcer
         (GetSidechains, GetSidechainProposals, GetWithdrawalBundleProposals)
      → pool shows what it voted, what everyone voted, and what happened

The enforcer speaks Connect, so the pool can call all of the above as plain
JSON over HTTP POST with no protobuf codegen:

    POST /cusf.mainchain.v1.BlockProducerService/GetBlockProducerState
    → {"ackAllProposals":true}

Worth noting that default: the enforcer ACKs every sidechain proposal unless
told otherwise. A pool that shows its miners a governance page should not be
silently voting yes on their behalf, so the pool must set an explicit policy at
startup rather than inherit that one.

## Protocol change

Raising the script cap is a change to the DATUM wire format, so both ends have
to agree. The cheapest version that is not a hack:

- Keep the existing `[value][len][script]` record for payouts, unchanged, so an
  unmodified gateway keeps working against a modified pool for the payout path.
- Add a second section for commitments, length-prefixed with two bytes rather
  than one, marked mandatory, and carried under a new coinbaser id so an old
  gateway ignores it rather than misparsing it.

The version negotiation already present in the DATUM handshake is where a
gateway declares it understands commitments; a pool talking to a gateway that
does not simply sends no commitment section, and mines without votes rather
than failing.

## Sidechain fees

Withdrawal bundles pay a fee to the mainchain miner that includes them. Those
arrive in the coinbase like any other value and should be split by the same
VIBES window as the block subsidy — a miner who contributed work to the window
earned their share of whatever that block collected, regardless of which
mechanism produced it. No special handling is expected beyond making sure the
value is counted; this needs confirming against a real bundle before it is
relied on.

## Staging

1. Pool reads and displays: sidechains, proposals, bundles, current ACK policy.
   No coinbase changes, nothing to break, immediately useful.
2. Pool records an operator's vote and holds it as policy.
3. Protocol: commitment section, version-negotiated.
4. Gateway: parse the section, reserve its size, insert before payouts, never
   trim.
5. Pool: recognise commitment outputs in the coinbase audit.
6. BMM: h\* commitments through the same path.
7. Read the results back and publish them.

Stages 1 and 2 are useful on their own and touch nothing that mines. Stage 3
onward cannot be tested until the enforcer is synced and serving templates.
