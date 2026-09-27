# ADS xDS cache state, publication, and rollback

## Overview

The cache stores xDS resources Cilium wants before Envoy accepts them. It owns the
transaction that changes desired resources, accumulates unpublished changes,
and retains enough information to recover from either a caller failure or an
Envoy NACK. A matching watch triggers snapshot construction and publication;
go-control-plane constructs and delivers protocol responses.

```text
Cilium update → desired state → watch → snapshot → response → ACK/NACK
                       │                              │
                caller lifecycle              response-owned rollback
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
- Strict response recovery can additionally revert newer dependent resources
  to preserve reference consistency.
- Cache mutations and completion registration are serialized under the cache
  lock. Response delivery and completion callbacks run after unlocking.
- Each NACK selects its inverses and applies their final correction under that
  same lock. No caller can interleave and no intermediate snapshot is published.
- Strict ADS validates affected references before changing desired state. A
  debug-only full snapshot check verifies the published projection separately.
- A matching open watch or the next request finalizes accumulated mutations.
  Without one, mutations do not construct snapshots or format wire versions.
- ACK/NACK processing uses the response's exact generation, named-resource
  coverage, stream, and nonce. A partial response cannot acknowledge names
  outside its subscription. For types supporting deletion by omission,
  an ACK can acknowledge removal of a requested name absent from the response.
- Caller `Revert()` and `Finalize()` are terminal, even when revert fails.
  Duplicate calls warn and do nothing. Failed response recovery instead keeps
  its payload for a later response.
- Sparse rollback state and removal tombstones (stored as a nil resource) remain
  only while live owners or transaction relationships need them.

## State and ownership

`nodeState` owns desired entries, desired/published generations, epoch negotiation,
optional `pendingPublication` bookkeeping, open watches, and the strict reference
index. Its embedded `rollbackState` manages live caller and response inverses,
transaction dependencies, and predecessor rebasing. Each `typeStates` slot groups
aggregate generations, first-request epochs, changed names, and an embedded
`resourceRollbackState` for unsent rollback and tombstone ownership. Rollback
maintenance lives in `rollback.go` and uses the existing cache lock; transaction
validation, desired-state changes, and publication remain in the cache.
A secondary name index selects response owners of dependent inverses without
scanning unrelated lifecycles. It retains only live relationships, is maintained
under the same cache lock, and applies in both strict and non-strict ADS modes.
Finalization clears changed names, not independent rollback; publication failure
restores saved generations without replacing whole records. Protocol strings
are converted to array indexes and bit sets at the boundary.

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

Desired entries share the `resourceMaps` layout with sparse inverse containers:

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

1. Compares candidates with desired state, preserving canonical pointers for
   semantic no-ops.
2. Prepares changes, records pending values reused unchanged, and reserves a
   generation when something changes.
3. Validates affected LDS/RDS and CDS/EDS references in strict ADS mode.
4. Commits entries, marks changed names, and registers ACK waits.
5. Coalesces sparse response inverses and their dependent transactions into
   `nodeState.pendingPublication`.
6. Finalizes immediately if a directly affected watch is open.
7. Creates any requested caller lifecycle after a successful commit/publication.

Readers cannot observe partial changes. Publication failure restores previous
entries, reference counts, changed names, and previous pending publication
bookkeeping, and detaches this transaction's waits; a failed apply returns no
caller lifecycle. A delivery error after go-control-plane installed the intended
snapshot is treated as a committed update. Installation is confirmed by exact
snapshot identity, not matching versions.
Unchanged-resource waits prepared earlier in a mixed transaction are also
detached on validation failure; unrelated pending state remains owned.

A per-node reference index counts Listeners referring to each Route and
Clusters referring to each Endpoint. It starts empty with the node and changes
only with committed mutations. Strict mode validates only child names affected
by a transaction, evaluating parent and child changes together. Missing
Routes and orphan Routes/Endpoints are rejected synchronously, before changing
desired state or registering rollback ownership. Missing CLAs are allowed:
publication synthesizes empty assignments without inserting them into desired
state. Compensating mutations use the same validation and publication path.

Non-strict mode and unrelated types skip the reference index. Only strict ADS
expands response rollback to preserve reference consistency. Losing the last
parent removes its child, and removing a Route restores or removes Listeners
that still require it. Shared children survive; content-only child reverts do
not cascade to parents. A full snapshot consistency check runs only with both
strict ADS and agent debug logging enabled; transaction safety does not depend
on that projection check.

### On-demand finalization

A successful mutation commits desired state before returning, not necessarily
a snapshot. While Envoy processes a response, subsequent mutations coalesce
without snapshot construction. A directly affected open watch or the next
matching request finalizes the pending publication. An unrelated watch does not
trigger it.

`pendingPublication` holds metadata and rollback state, not a snapshot or a
second resource map. Unpublished changes are already in desired state. Its
indexed `rollbacks` map also marks types needing completion finalization.
A present, empty value requires finalization but no new inverse,
including coalesced A-B-A changes and compensating publications.

Known nodes start with desired state, not a prebuilt empty snapshot. Their first
supported active subscription publishes desired state if no snapshot exists;
explicitly cleared delivery state is handled the same way. Empty groups are
supplied only when the corresponding desired group is empty.

Incremental finalization shallow-copies snapshot slots and replaces affected
groups. A group's immutable resource map is cloned only when an entry changes.
Each group contains `cache.Resources` and its aggregate generation, including
synthesized empty CLAs in the projection. Snapshot construction does not marshal
or hash resources: go-control-plane marshals them when constructing a response.
SotW snapshots omit per-resource version maps.

A Cluster change can require fresh EDS delivery even when desired CLAs are
unchanged: to finish warming with an already-subscribed EDS name, or because
the snapshot gains or loses synthesized empty assignments. In these cases,
the EDS wire generation advances to `max(EDS generation, CDS generation)`,
so an unchanged version cannot suppress the response. Desired CLA revisions
and transaction IDs remain unchanged.

LDS changes do not artificially advance RDS, CDS or SDS versions. Collected
response batches are delivered in dependency order.

Cache relays buffer responses produced synchronously by `SetSnapshot` or
`CreateWatch`. Their exact generation, named-resource coverage, and rollback
ownership are captured before delivery outside the lock. Publication metadata
becomes visible only after successful installation. A slow consumer cannot hold
up mutations.

A `CreateWatch` finalization error leaves desired state and pending publication
bookkeeping available for another attempt or caller rollback. Encoding errors
belong to response construction, not mutation or snapshot finalization; a
successful mutation does not prove the resource can be encoded or delivered.
After successful installation, `snapshotGeneration` advances, and pending
publication bookkeeping and changed-name sets are cleared.

## Generations and no-op waits

Wire versions use `e<epoch>:g<generation>`, for example `e1:g42`. The cache keeps
bare generations internally and binds the node epoch when finalizing a snapshot.
Each TypeURL's aggregate generation advances for real changes, compensation,
and EDS replay. Failed attempts can leave gaps in the cache-wide sequence, which
is never rewound. Three types distinguish how its numbers are used:

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

In `A → B → A`, the two API changes to A have different transaction IDs,
revisions, and wire versions even when their contents match. An old inverse
cannot revert a later A. Coalescing can still produce a redundant response
for already accepted contents. Reverts instead restore the previous transaction
while advancing its revision: the value came from the original API transaction,
but restoring it is a new revision. Thus a delayed ACK for B, or for the original
A, cannot complete a new wait for restored A.

The first request for each TypeURL contributes its reported epoch. Versions
without an `e<positive integer>:` prefix are ignored. The first node epoch is the
smallest positive integer absent from that request. If a later TypeURL reports
that selected epoch, negotiation advances beyond every first-request epoch
retained in the node's type slots. This avoids collisions when Envoy retained
different resource-type epochs across agent restarts.

Already negotiated types retain continuity across reconnects. Epoch rotation
shallow-copies the published protocol view, sharing immutable maps, and does not
publish unrelated unpublished changes. Persistent known nodes retain their
negotiated epoch even with no resources or streams.

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
Changing one name must not make unchanged, ACKed names wait again. The pending
publication or published snapshot generation is the fallback for a whole-type
wait. If no published baseline exists, waits register against desired revisions
and acquire their wire version at the next successful publication. A no-op
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
list. That change can be ACKed or NACKed and retains its response inverse,
including while publication is still pending.

ACK releases response-owned rollback state only after all required
resource names have been acknowledged.

### Triggering resource changes and transaction members

A **triggering resource change** is a tracked change belonging to the NACKed
response's TypeURL, not a transaction or necessarily the particular resource
Envoy found invalid. If one API transaction adds a Listener and a Cluster, the
Listener change can trigger rollback on an LDS NACK, and the Cluster change can
trigger it on a CDS NACK. Both are members of the same transaction.

Coalescing several transactions into one response does not merge their rollback
eligibility. A triggering resource change that still matches desired state makes
its transaction's other still-current members eligible for rollback. Changes
superseded by another change in the same rejected batch retain their predecessor
chain. An independently superseded triggering change does not, by itself, make its
transaction’s other members eligible for rollback.

For example, transaction A adds Listener `l1` and Cluster `c1`, and B adds `l2`
and `c2`. Both Listeners are sent together, and CDS ACKs both Clusters. If another
transaction replaces `l1` before the LDS NACK, the NACK reverts `l2` and `c2`,
but preserves the newer `l1` and A's `c1`. Later inverses which restore `c1`
must also keep that target. The rejected old `l1` is still bypassed in later
inverses, so reverting its replacement cannot resurrect it.

If a later inverse would restore a rejected triggering value and other values
from that same predecessor transaction together, rebasing bypasses that whole
predecessor. An independent inverse restoring only a preserved member does not.

Transaction-member selection applies in both ADS modes. **Companion** refers
only to the additional resource changes required for strict-ADS consistency,
not to members of an API transaction.

In both ADS modes, a NACK reverts the rejected transaction and later transactions
that reused its pending values, including transactions without a WaitGroup.
Dependencies are transitive and survive caller finalization and ACKs for other
resource types. Outstanding dependent waits also fail. Caller waits remain
independent of inverse coalescing, so replacing a pending value cannot lose
earlier waits.

For example, transaction A adds Listener `l1`; B supplies the same pending `l1`
and adds Secret `s1`. An LDS NACK for A also reverts B's still-current `s1`,
even if SDS already ACKed it.
An independently newer `l1` can skip A's inverse without protecting B's
still-current dependent `s1`.

Named responses acknowledge only prerequisites they contain. If a transaction
has multiple pending prerequisites, ACKing one does not release recovery state
for the others; a NACK for any of them triggers rollback. Bookkeeping retains
only live dependency relationships, not a history of earlier mutations.

NACK recovery uses the ordinary cache transaction. It takes the cache lock
before revalidating the response and claiming inverses under the callbacks
lock, then releases the callbacks lock to prepare one final correction.
The cache lock prevents caller mutations and other NACKs from interleaving.
Only the final state is validated and committed; intermediate restored values
cannot be delivered or acquire new waits.

Selected inverse targets are composed oldest first, bypassing rejected
predecessors in pending-publication, live response, and caller inverses.
Superseding API transactions remain guarded. For example, if A is rejected
after B replaces it, B remains desired, but its later rollback restores the
value before A, not A. This applies to unsent responses and caller rollback
after B is ACKed too. Only live inverses are retained, not a history of
rejected values.

Successful recovery consumes the selected inverses together and commits one
corrective generation. A matching open watch can consume it immediately;
otherwise finalization waits for the next watch. Response delivery and
application callbacks run after unlocking.

Failed validation or publication leaves desired state unchanged and retains
the batch's response inverses for a later response. Rejected predecessors are
still bypassed in other inverse targets: rejection is definitive even if
corrective publication fails. Caller waits receive the original NACK, and the
recovery error closes the stream. An ACK can release retained recovery state;
there is no background retry loop. Caller reverts remain transaction-fenced and
may still fail validation.

### Removal tombstones

A nil resource with a nonzero transaction identifies a removal. Node-local owner
counts, keyed by type, name, and transaction, retain tombstones for caller,
pending publication, unsent, and response inverses. The last owner releases the
tombstone. Unsent add/remove chains that become no-ops can release their inverse
and tombstone without consuming independently owned caller rollback.

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

- `resources.go`: containers, prepared changes, and input validation.
- `node_state.go`: desired mutations, changed names, pending publication,
  reference validation, epoch negotiation, rollback coalescing, and tombstone
  ownership.
- `cache.go`: locking, snapshot construction/publication, response delivery,
  and rollback lifecycles.
- `callbacks/`: response identity, named-resource coverage, accepted state, waits,
  NACK recovery in `nack.go`, and stream lifecycle tracking in `streams.go`.

Tests for resource and node-state helpers live alongside those files. Cache
API/lifecycle tests use the public mutation APIs; watch and named-resource coverage tests drive
real go-control-plane responses and stream callbacks.
