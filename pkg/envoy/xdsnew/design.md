# ADS xDS cache state, publication, and rollback

## Overview

The cache stores xDS resources Cilium wants before Envoy accepts them. It owns the
transaction that changes desired resources, publishes an immutable snapshot,
and retains enough information to recover from either a caller failure or an
Envoy NACK. go-control-plane constructs and delivers protocol responses.

```text
Cilium update → cache transaction → published snapshot → response → ACK/NACK
                    │                                    │
             caller lifecycle                    response-owned rollback
```

These are three distinct resource views:

| View | Meaning |
| --- | --- |
| Desired | Mutable cache-private maps of immutable protobufs. |
| Published | The latest immutable snapshot installed in go-control-plane. |
| Accepted | Resources acknowledged by Envoy, tracked by name for partial responses. |

Publication alone proves neither delivery nor acceptance. Caller rollback and
response rollback have independent lifetimes: finalizing an endpoint
regeneration must not prevent a later Envoy NACK from correcting the cache.

Named-resource coverage identifies the resource names whose state a particular
response communicates, including deletions where omission signals removal.

## Principal invariants

- Supported nodes are fixed at construction. Their `nodeState` persists with
  empty resources and no streams; requests and mutations never create nodes.
- Every real mutation allocates a cache-wide `Generation`, assigned as the
  `Revision` of each changed named value. API changes set the entry's
  `TransactionID` to that same number; semantic no-ops preserve the protobuf
  pointer and both properties.
- Reverts change an entry only if its `transaction` still matches the expected
  API transaction. They restore the previous value and transaction but assign a
  fresh revision. Older ACKs cannot accept restored state.
- Cache mutations and completion registration are serialized under the cache
  lock. Response delivery and completion callbacks run after unlocking.
- Each NACK selects its inverses and applies their final correction under that
  same lock. No caller can interleave and no intermediate snapshot is published.
- ACK/NACK processing uses the response's exact generation, named-resource
  coverage, stream, and nonce. A partial response cannot acknowledge names
  outside its subscription. For types supporting deletion by omission,
  an ACK can acknowledge removal of a requested name absent from the response.
- Caller `Revert()` and `Finalize()` are terminal, even when revert fails.
  Duplicate calls warn and do nothing. Failed response recovery instead keeps
  its payload for a later response.
- Sparse rollback state and removal tombstones (stored as a nil resource) remain only while live owners or
  transaction relationships need them.

## State and ownership

`nodeState` owns desired entries, desired/published generations, open watches,
and a `rollbackState` containing live caller and response inverses for predecessor
rebasing. Each TypeURL's `resourceRollbackState` owns its unsent inverse and
tombstone-owner counts. Rollback methods borrow desired-state or transaction
context and share the cache lock; they neither lock nor invoke user callbacks.
Supported types use
fixed array slots and bit sets; TypeURL strings are converted at the boundary.
Requests for unsupported TypeURLs from configured nodes call the embedded
go-control-plane cache's `CreateWatch`, without Cilium's per-TypeURL tracking.
Cilium never publishes resources for these types. An initial request with an
empty version remains unanswered until cancellation; a request with a nonempty
version may receive an empty response.

Completion callbacks own caller ACK waits, accepted-resource evidence, pending
response identities, and rollback claimed by a response. Accepted state retains
the relevant immutable resource group and sparse subset overrides, not whole
older snapshots. Multiple streams keep independent response identities for the
same node and TypeURL.

Desired maps and inverse containers share the `resourceMaps` layout:

```text
resourceEntry {
    resource:    immutable protobuf, or nil for removal
    revision:    Revision of the current named value, regardless of change source
    transaction: TransactionID of the API call which inserted or deleted this value
}
```

The `resources` container keeps a single inverse inline and uses maps for larger
inverses. A zero inverse entry records prior absence. `resourceChanges` contains
previous/next entries, with one change inline and further changes in a slice.
Those previous entries also restore failed publications without allocating
another inverse.

`ApplyResource` takes a TypeURL index, name, and protobuf; nil removes it.
`ApplyResources` accepts sparse LDS/RDS/CDS/EDS/SDS transactions. Its
`xds.Resources` input has no NPDS/NPHDS fields, so one transaction cannot mix
Listener and NetworkPolicy changes. Only `WithRollback` variants return a
caller lifecycle; all mutation APIs independently retain needed NACK state.

## Transactions and publication

A transaction holds the cache write lock while it:

1. Compares candidates with desired state and prepares actual changes.
2. Reserves a generation, commits desired entries, and registers ACK waits.
3. Constructs a snapshot and checks full consistency in strict ADS mode.
4. Installs it and records successful publication.
5. Creates a caller lifecycle, if requested, only after publication succeeds.

Readers cannot observe partial changes. Publication failure restores previous
entries and detaches this transaction's waits; a failed apply returns no caller
lifecycle. A delivery error after go-control-plane installed the intended
snapshot is treated as a committed update. Installation is confirmed by exact
snapshot identity, not matching content versions.

Strict mode rejects missing Routes and orphan Routes/Endpoints synchronously,
restoring desired state before returning an error. Missing CLAs are allowed:
snapshot construction synthesizes empty assignments without inserting them into
desired state. Non-strict mode skips the explicit consistency check.
Compensating mutations use the same validation and publication path.

### Snapshot delivery

A successful real mutation installs a snapshot before returning. An open watch
may consume it immediately; otherwise it is available to later requests. Known
nodes start with desired state, not a prebuilt empty snapshot. Their first
supported active subscription publishes desired state if no snapshot exists.

Each snapshot group contains `cache.Resources` and its per-resource content
versions, constructed together from the published projection, including
synthesized CLAs. `ConstructVersionMap` does no additional work. Dependency
version contexts can advance a companion group's protocol version without
changing its protobufs. A corrective publication also includes its fresh
generation in the affected type's version, so restoring identical contents
cannot reuse an earlier response's ACK.

Cache relays buffer responses produced synchronously by `SetSnapshot` or
`CreateWatch`. Their exact generation, named-resource coverage, and rollback ownership are
captured before delivery outside the lock. Publication metadata becomes visible
only after successful installation. A slow consumer cannot hold up mutations.

## Generations and no-op waits

Content hashes remain protocol versions; the shared generation sequence establishes
internal mutation order. Failed attempts can leave gaps, and the sequence is
never rewound. Three types distinguish how its numbers are used:

- `Generation`: a reserved mutation number, or a snapshot/response boundary.
- `Revision`: when a named value last changed, whether by an API call or revert.
- `TransactionID`: the API call which originally inserted or deleted that value.

Snapshot and response boundaries remain `Generation`s because they can include
several API transactions and reverts, not just one named value or API call.
ACK evidence must reach the required revision **and** cover that resource name;
a newer boundary alone does not prove acceptance.

All three roles draw from one cache-owned generation source. API changes assign
the same number to the value's revision and transaction ID. Reverts assign a fresh
revision but restore the previous transaction ID. Ordering across these roles
relies on their shared source.

Wait boundaries can include revisions; response rollback boundaries can include
transaction IDs. An inverse uses the transaction's initial revision, whereas
a caller wait requires the current revision.

In `A → B → A`, equal content versions do not make two independent API changes
the same transaction. An old inverse cannot revert a later A. Reverts instead
restore the previous transaction while advancing its revision: the value came
from the original API transaction, but restoring it is a new revision. Thus a
delayed ACK for B, or for the original A, cannot complete a new wait for restored A.

A semantic no-op allocates no generation or caller inverse. Its ACK wait checks
the specific resource:

- Already accepted contents complete immediately, even if another name of the
  same type is pending.
- Pending state waits for a response covering that revision and name.
- A known NACK for that state can fail the wait immediately.

Single-resource waits use the entry's revision directly.
Restored absence uses the type's latest corrective generation without retaining
per-name tombstones solely for waiting. Bulk waits use matching names
per type, retaining only names whose desired contents are not already accepted.
Changing one name must not make unchanged, ACKed names wait again. The published
generation is the fallback for a whole-type wait.
If no published baseline exists, waits register against desired revisions
and acquire their content version at the next successful publication. A no-op
does not force publication merely to register a wait. Removals from a pristine
known node still complete immediately because no mutation needs acknowledgment.
Responses carry their exact publication, including immediate `CreateWatch`
responses wrapped under the lock. Generations are never inferred from later
publications or newly registered waits.

`OnStreamResponse` associates generations and named-resource coverage; it does not complete
waits. ACK/NACK arrives in the subsequent request. A multi-name wait succeeds
only after all required names have been ACKed.

## Rollback ownership and lifetime

The caller eventually invokes exactly one lifecycle method:

- `Finalize()` releases its inverse without changing desired resources.
- `Revert()` attempts the transaction-fenced inverse, returns any error, and
  releases caller ownership whether it succeeds or fails.

An Envoy ACK can precede a later regeneration failure, so caller rollback must
remain usable after ACK. Conversely, caller cancellation, timeout, or early
finalization cannot consume response rollback.

Unsent response inverses coalesce per type and name:

```text
desired changes: P0 → P1 → P2 → P3
inverse: previous=P0, expectedTransaction=transaction(P3)
```

A net no-op unsent chain can discard its inverse, even with different protobuf
pointers. Response collection stops coalescing its claimed rollback; subsequent
updates start another chain. NACK recovery may still rebase an inverse's target
to bypass a rejected predecessor. A sent inverse cannot be discarded just because
desired contents return to the original value: Envoy could still NACK it.

A named response claims rollback state for the transactions it covers.
Keep all still-current changed members of each such transaction together,
even if the response delivers only some of them.

For SotW EDS/RDS/SDS, omitting a resource does not tell Envoy to delete it.
Envoy may retain its previous configuration while a parent still references
it. A removal that leaves the resource absent from the snapshot therefore
needs no response-owned inverse, unless another changed member of the same
transaction can be NACKed and require the whole transaction to be undone.

Removing a CLA still referenced by a cached Cluster is different: the
snapshot supplies a named, empty CLA, explicitly replacing its old endpoint
list. That change can be ACKed or NACKed and retains its response inverse.

ACK releases response-owned rollback state only after all required
resource names have been acknowledged.

NACK recovery uses the ordinary cache transaction. It takes the cache lock
before revalidating the response and claiming inverses under the callbacks
lock, then releases the callbacks lock to prepare one final correction.
The cache lock prevents caller mutations and other NACKs from interleaving.
Only the final state is validated and published; intermediate restored values
cannot be delivered or acquire new waits.

Selected inverse targets are composed oldest first, bypassing rejected
predecessors in all live response and caller inverses. Superseding API
transactions remain guarded. For example, if A is rejected after B replaces it,
B remains desired, but its later rollback restores the value before A, not A.
This applies to unsent responses and caller rollback after B is ACKed too.
Only live inverses are retained, not a history of rejected values.

Successful recovery consumes the selected inverses together and publishes one
corrective generation. Restored values receive fresh revisions even when a
sent A-B-A chain restores identical protobuf contents. Response delivery and
application callbacks run after unlocking.

Failed validation or publication leaves desired state unchanged and retains
the batch's response inverses for a later response. Rejected predecessors are
still bypassed in other inverse targets: rejection is definitive even if
corrective publication fails. Caller waits receive the original NACK, and the
recovery error closes the stream. An ACK can release retained recovery state;
there is no background retry loop.

### Removal tombstones

A nil resource with a nonzero transaction identifies a removal. Node-local owner
counts, keyed by type, name, and transaction, retain tombstones for caller,
unsent, and response inverses. The last owner releases the tombstone. Unsent
add/remove chains that become no-ops can release their inverse and tombstone
without consuming independently owned caller rollback.

## Disconnect, reconnect, and startup

Disconnect cancels that stream's watches and removes its response identity, not
desired state or recovery payloads. Sent, unacknowledged rollback loses the dead
stream/nonce association but stays frozen; unsent rollback remains coalescible.
Other live streams keep their state. When the last stream closes, acceptance
evidence is cleared because reconnect might involve a fresh Envoy process.

A reconnecting supported node can receive retained generations again. An echoed
version alone does not prove acceptance of names never delivered: named-resource
coverage and ACK/NACK must establish their outcome.

Before the first connection, repeated changes to one name keep an absent or
oldest baseline and the latest expected API transaction. Caller finalization does
not remove that response inverse; an initial NACK can therefore remove applicable
cold-created resources.

There is no per-mutation snapshot queue. Frozen inverses can still remain while
Envoy is disconnected. Repeated response/disconnect cycles without outcomes can
retain several frozen lifecycles; a later response can resolve covered
generations together.

## Listener-derived policy waits

The ADS-supplied `ListenerObserver` counts desired listeners starting an NPDS
client. It runs under the cache lock and must not take the ADS server mutex or
call the cache. NACK reverts are included; bulk replacement exposes only its net
listener-count change.

Under the same lock, a NetworkPolicy update without NPDS listeners stores desired
state but immediately succeeds its caller wait. Removing the last listener
detaches existing node-scoped NPDS waits before unlocking and completes them
afterward. A concurrent addition cannot cancel its new waits accidentally.
This success resolves ACK waits only, not acceptance or rollback ownership.

## Code organization

- `resources.go`: containers, prepared changes, input validation.
- `node_state.go`: desired mutations, rollback coalescing, tombstone ownership.
- `cache.go`: transactions, publication, response delivery, rollback lifecycles.
- `callbacks/`: response identity, named-resource coverage, accepted state,
  waits, and NACK recovery phases in `nack.go`.

Tests for resource and node-state helpers live alongside those files. Cache
API/lifecycle tests use the public mutation APIs; watch and named-resource coverage tests drive
real go-control-plane responses and stream callbacks.
