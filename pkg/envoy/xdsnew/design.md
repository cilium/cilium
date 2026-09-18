# ADS xDS Revert and Rollback State Management

## Purpose

Cilium updates its xDS cache before Envoy has accepted the resulting configuration. Those changes may need to be undone for two independent reasons:

1. A broader Cilium operation, such as endpoint regeneration, fails after updating the xDS cache.
2. Envoy rejects an xDS response with a NACK.

The rollback system must handle both cases without:

- reverting newer resource updates;
- confusing repeated content states in an A → B → A sequence;
- losing rollback state when a caller times out;
- retaining a complete cache snapshot for every mutation;
- accumulating unnecessary rollback state while Envoy is slow or disconnected.

The new design uses sparse inverse mutations, internal generation numbers, separate caller and response lifetimes, and per-resource generation checks.

## Terminology

### Revert

A revert applies an inverse mutation and attempts to restore the resource state that existed before an update.

### Finalize

A finalize operation declares that a particular rollback opportunity is no longer needed. It releases the associated rollback state without changing the desired resources.

### Rollback lifecycle

A rollback lifecycle implements `revert.Revertible` and owns rollback state
until exactly one outcome is selected:

- `Finalize()` releases it after the enclosing transaction succeeds; or
- `Revert()` restores the previous state after the enclosing transaction fails.

Calling either method again is treated as a programming error, but it is deliberately harmless: the call emits a warning and does nothing.

### TypeURL

Envoy ACKs and NACKs resources independently by xDS resource type, such as:

- Listener
- Cluster
- RouteConfiguration
- Secret
- Cilium NetworkPolicy

Response-owned rollback state is therefore kept separately for each TypeURL.

Cilium manages a fixed set of seven resource types. Internally, each supported
TypeURL is represented by a small array index, so per-type snapshot, watch,
completion, and rollback state uses fixed slots and bit sets rather than
string-keyed maps. Protocol TypeURL strings are converted only at the
go-control-plane boundary. Unknown protocol types bypass Cilium's bookkeeping
and retain go-control-plane's behavior.

## The three resource-state views

For each Envoy node, the cache distinguishes three views of resource state.

### Desired state

This is what Cilium currently wants Envoy to have.

It is mutable, private to the cache, and updated immediately when Cilium performs a resource mutation.

### Published snapshot

This is the most recent immutable go-control-plane snapshot made available to Envoy.

The desired state can be ahead of the published snapshot while mutations are staged.

The snapshot uses one fixed slot per supported TypeURL. Each slot keeps the
published resources and the generation and dependency context used to derive
its aggregate SotW version. The snapshot retains protobuf objects, not
serialized bytes. go-control-plane marshals resources when a response is
encoded.

Incremental finalization shallow-copies the fixed slots and replaces only the
affected resource groups. Within an affected group, the immutable resource map
is cloned only when its entries change. Snapshots carry only aggregate SotW
versions; they do not retain per-resource generation or version maps.

### Accepted snapshot

This records the resource contents Envoy most recently ACKed for each TypeURL.

The published snapshot can be ahead of the accepted snapshot while Envoy processes a response.

The relationship is therefore:

```text
accepted state ≤ published state ≤ desired state
```

The states can temporarily be equal, but they have different responsibilities.

## Generations and xDS versions

The implementation uses generation numbers for both internal ordering and xDS
version strings, with an epoch separating different agent instances.

### Wire format and epoch

xDS versions have this form:

```text
e<epoch>:g<generation>
```

For example, `e1:g42` identifies generation 42 in epoch 1.

The cache negotiates one epoch for each node ID. The first request for each
TypeURL contributes the epoch it reports; versions without an
`e<positive integer>:` prefix are ignored. Each resource-type slot retains the
greatest epoch from that first request. The initial node epoch is the smallest
positive integer absent from the first request. If a later TypeURL reports the
selected epoch, the cache advances beyond every epoch retained by the slots.

This makes versions from a restarted agent distinct from versions retained by
the longer-running Envoy process, including when Envoy retained different
epochs for different resource types after partial agent restarts. An already
negotiated TypeURL reporting the selected epoch on a later stream is ordinary
continuity and does not rotate it again.

Each resource-type slot also records the epoch under which it was negotiated.
The cache stores bare generations in desired state and binds the node epoch
when a snapshot is finalized for a consumable watch. Rotating the epoch
shallow-copies and reinstalls the protocol view for all TypeURLs without
copying resource maps or publishing unrelated staged desired state.

### Generations

A generation is an internal monotonically increasing sequence number allocated for each real resource mutation.

Generations establish mutation order even when contents repeat.

For example:

```text
generation 10: A
generation 11: B
generation 12: A
```

Generations 10 and 12 have different xDS versions even though their resource
contents are equal.

This avoids content hashing and the ambiguity of using equal content hashes for
internal ordering.

## Generation-tagged desired resources

Each resource stored in the cache-private desired state contains:

```text
resource pointer
generation that most recently changed this resource name
```

Desired resources use the same fixed TypeURL slots as published snapshots.
Each slot keeps that resource type's entries together with the sparse set of
names changed since publication. Resource values are stored through the
protobuf message interface; the slot identifies their concrete protobuf type.
Typed mutation APIs convert at the cache boundary, while internal publication
and rollback code can operate uniformly across resource types. Sparse inverse
state keeps one entry inline and uses map-only slots for larger updates;
restored entries also use map-only slots. Neither carries unused changed-name
sets.

A transaction's prepared changes are separate from the public `xds.Resources`
input. The common single-resource update stays inline; a bulk update uses a
slice of TypeURL-indexed changes rather than allocating removed and upserted
maps for each type. Each change retains the previous entry for rollback, and
only changes that survive semantic equality checks are committed.

`xds.Resources` contains only LDS/RDS/CDS/EDS/SDS resources. NPDS and NPHDS
use typed cache operations, including an NPDS-only bulk removal. Thus a cache
transaction cannot change listeners and network policies together, even when
their separate updates coalesce into one snapshot sent to Envoy.

Conceptually:

```text
resourceEntry {
    resource:   P1
    generation: 42
}
```

Resources are immutable protobuf objects, so rollback state can safely retain their pointers without deep-copying them.

A removal is represented temporarily as:

```text
resourceEntry {
    resource:   nil
    generation: 42
}
```

This is a removal tombstone. It preserves information about which generation removed the resource.

## Processing a real mutation

Suppose a NetworkPolicy named `P` changes from `P0` to `P1`.

The cache first checks whether the resource changed semantically:

1. Compare pointers.
2. If the pointers differ, use generated VT equality when available and fall
   back to `proto.Equal` otherwise.

If the contents are equal, the operation follows the no-op path described later.

For a real change, the cache:

1. Allocates generation 42.
2. Captures the previous entry for `P`.
3. Updates the cache-private desired state in place.
4. Marks `P` as changed since the last publication.
5. Creates caller-owned rollback state.
6. Merges the inverse into staged response-owned rollback state.

The desired state becomes:

```text
P = {
    resource:   P1
    generation: 42
}
```

The sparse inverse is conceptually:

```text
P = {
    previous:           P0
    expectedGeneration: 42
}
```

The inverse contains only resources changed by this mutation. It does not retain a copy of the complete node state or snapshot.

## Per-resource generation fencing

Before restoring a resource, rollback compares its current generation with the rollback entry’s expected generation.

For the preceding example:

```text
current generation == 42
expected generation == 42
```

The resource can safely be restored to `P0`.

If another update has changed it:

```text
current generation == 43
expected generation == 42
```

the rollback skips that resource.

This is the central safety rule:

> A rollback may change a resource only while that resource still belongs to the generation being reverted.

Generation checks are performed per resource name. A rollback may therefore restore some resources while skipping others that have been updated more recently.

## Two independent rollback lifetimes

Every real resource mutation may need rollback for two independent reasons:

```text
                         Cilium mutation
                               │
             ┌─────────────────┴─────────────────┐
             │                                   │
      caller-owned rollback              response-owned rollback
             │                                   │
     endpoint regeneration                 Envoy protocol
       success / failure                    ACK / NACK
```

These are separate rollback lifecycles derived from the same sparse inverse state.

## Caller-owned rollback

`UpdateNetworkPolicy` returns one `Revertible`. The endpoint-regeneration
caller must eventually invoke exactly one of its outcome methods.

### Caller revert

If broader endpoint regeneration fails, the caller invokes `Revert()`.

The cache restores only resources that still belong to that update’s generation. Newer resources are preserved.

### Caller finalize

If endpoint regeneration succeeds, the caller invokes `Finalize()`.

This releases caller-owned rollback state without changing resources.

### Update paths without external rollback

Most other xDS update operations do not expose rollback to their callers.

Those paths finalize their caller-owned rollback immediately after the cache mutation. Response-owned rollback remains independently available for a later Envoy NACK.

## Response-owned rollback

The cache separately retains rollback state for the xDS response that will eventually represent the mutation.

This lifetime is independent of:

- the caller’s WaitGroup;
- the caller’s context;
- caller timeout;
- caller terminal completion;
- endpoint regeneration completion.

Response-owned rollback terminates when:

- Envoy ACKs the response;
- Envoy NACKs the response;
- the cache determines that the resource contents cannot produce a new response.

This separation settles an important ownership problem, allowing the cache to properly process Envoy NACKs independently of the caller behavior.

Caller revert restores each affected resource only if it still has the generation being reverted; resources with newer desired state are left unchanged. If caller revert restores a resource, a later NACK skips that resource because the response rollback's expected generation no longer matches. A later ACK does not mutate resources; it completes any associated waiters and releases response-owned rollback state.

For example:

1. Envoy ACKs the xDS response.
2. Broader endpoint regeneration subsequently fails.
3. Caller-owned rollback restores the previous desired state.
4. The cache publishes a corrective snapshot to Envoy.

Caller finalize releases only caller-owned rollback. Response-owned rollback remains and can restore the rejected state.

## Staged rollback coalescing

Resource mutations can arrive faster than Envoy consumes snapshots. The cache therefore stages changes and coalesces their response rollback state.

Suppose one policy changes repeatedly before a response is produced:

```text
P0 → P1 → P2 → P3
```

The cache does not retain three complete response rollback records.

Instead, the coalesced entry becomes:

```text
previous:           P0
expectedGeneration: generation of P3
```

The coalesced rollback retains:

- the oldest state needed to undo the batch;
- the newest generation needed to verify that the batch is still current.

If Envoy NACKs the eventual response containing `P3`, the cache restores `P0`.

Different resource names have separate sparse rollback entries. Repeated updates to the same name do not make rollback state grow once per update.

## TypeURL-scoped rollback

Response rollback is divided by directly changed TypeURL.

A broader snapshot update may cause versions for dependent resource types to be regenerated. For example, a Listener change can affect version contexts involving other resource types.

However, an Envoy NACK rejects one TypeURL at a time. The cache therefore retains rollback only for resource types directly mutated by the transaction.

Consequently:

- a Secret NACK reverts Secret changes;
- a Listener NACK reverts Listener changes;
- a Secret NACK cannot roll back a NetworkPolicy merely because both appeared in the same snapshot.

Strict ADS adds one deliberate exception for go-control-plane snapshot
consistency. CDS and EDS form one consistency pair, as do LDS and RDS. A
rollback registered for either member also captures companion resources
changed by the same transaction, so rejecting CDS can restore the matching EDS
state and rejecting LDS can restore the matching RDS state. This does not pull
unrelated resource types into the rollback.

## Staged, published-but-unsent, and response-owned states

Response rollback progresses through three stages.

### 1. Staged

Desired resources have changed, but no snapshot has been finalized.

While staged:

- updates are applied directly to cache-private desired-state maps;
- changed resource names are recorded;
- rollback is coalesced per TypeURL and resource name;
- no protobuf marshaling or hashing is required.

If no relevant Envoy watch exists, the cache stays in this state.

### 2. Published but unsent

When an appropriate watch can consume the update, the cache incrementally generates a new immutable snapshot.

Only changed resource names and dependency-dirty types are considered. The
aggregate TypeURL version is formatted from its generation.

Generation versions advance across A → B → A changes. This may produce a new
SotW response even when the final protobuf pointer equals the previously
published one, but it avoids reintroducing a content comparison or hash at
publication time.

For changed versions, the cache retains at most one coalesced unsent rollback lifecycle per node and TypeURL.

Snapshot finalization does not serialize protobufs or calculate content hashes.
go-control-plane performs serialization only for resources included in an
actual response.

### 3. Response-owned

When go-control-plane actually produces a response, the cache marks the corresponding rollback as claimed by that response.

It is then owned by completion processing until the response is ACKed or NACKed.

Newer mutations cannot be merged into an already-produced response. They form the rollback state for the next response.

## Associating updates with responses

Each finalized snapshot has an internal snapshot generation.

Immediately before go-control-plane sends a response, the `CompletionCallbacks.OnStreamResponse` stream hook determines the snapshot generation and associates each registered completion and response-owned generation for the same node and TypeURL, whose generation is no newer than the snapshot, with that response generation.

Earlier staged mutations may already have been folded into one coalesced response rollback, so they do not necessarily have separate pending-generation entries.

Conceptually:

```text
mutation generations 40, 41, 42
                   ↓
       response generation 42
```

An ACK or NACK for that response can then resolve every mutation represented by it.

The formatted generation version is used by the wire protocol, while the
numeric generation handles internal ordering without reparsing strings.

The response is also matched using its node, TypeURL, stream, and nonce. An ACK or NACK from an old stream or for a stale nonce cannot resolve a newer response.

## ACK handling

When Envoy ACKs a response:

1. The callback verifies the stream and nonce.
2. Every completion attached to that response generation succeeds.
3. Response-owned rollback state is finalized.
4. Retained old resource pointers are released.
5. Removal tombstones with no remaining rollback owners are deleted.
6. The accepted snapshot for the TypeURL is updated.

Caller-owned rollback remains independent and is not released by the ACK.

## NACK handling

When Envoy NACKs a response:

1. The callback verifies the stream and nonce.
2. Only rollback state for the rejected TypeURL is selected.
3. Coalesced rollback lifecycles are processed newest-first.
4. Each resource is checked against its expected generation.
5. Resources that still belong to the rejected update are restored.
6. Resources superseded by newer updates are skipped.
7. The restored desired state is staged for delivery to Envoy.
8. Completions attached to the rejected response fail with the NACK error.

Processing newest-first allows older coalesced rollback entries to become applicable after a newer rollback restores the generation they expect.

## Older response NACK after a newer update

Consider this sequence:

```text
generation 42: P0 → P1
response containing P1 is sent

generation 43: P1 → P2
P2 has not yet been sent
```

The desired state now contains:

```text
P = {
    resource:   P2
    generation: 43
}
```

If Envoy NACKs the generation-42 response, its rollback expects generation 42.

Because the current resource is generation 43, the old NACK does not touch `P2`. A later response will carry `P2` and receive its own ACK or NACK.

This differs from updates coalesced into one response:

```text
P0 → P1 → P2
```

If neither intermediate state was sent and the eventual response contains `P2`, its coalesced rollback expects the generation of `P2` and restores `P0` if that response is NACKed. If the update to `P1` registered an ACK waiter, that completion is also attached to the coalesced response and completes with the NACK error; there was no separate response containing only `P1`.

## Interaction between caller and response rollback

Caller-owned and response-owned rollback can race safely because both are generation-fenced.

### Response NACK happens first

1. Response rollback restores the old resource.
2. Caller later invokes `Revert()`.
3. The caller rollback no longer finds its generation.
4. It performs no resource mutation and releases its state.

### Caller revert happens first

1. Caller rollback restores the old resource.
2. Envoy later NACKs the original response.
3. Response rollback no longer finds its expected generation.
4. It performs no resource mutation and releases its state.

### Caller finalize happens first

1. Caller-owned state is released.
2. Response-owned state remains.
3. A later NACK can still restore the rejected resources.

Normal endpoint regeneration with a policy-requiring Envoy listener waits for its proxy completion before finalizing or reverting the caller-owned `Revertible`. This typically eliminates the caller-finalize-before-NACK case, but correctness must not depend on it: initial policy publication and explicit
no-wait paths can finalize without an Envoy response, while an ACK can arrive before a later regeneration step fails and invokes caller revert. Caller-owned and response-owned rollback therefore remain independent in every path.

Calling `Finalize` or `Revert` after the lifecycle has already been resolved emits a warning and otherwise does nothing.

## Removal tombstones

A removed resource cannot always be deleted from the desired-state map immediately.

Consider:

```text
generation 40: resource exists
generation 41: resource removed
generation 42: resource recreated
generation 43: stale NACK for generation 41
```

If generation 41 had left no tombstone, rollback could not reliably determine whether the absence was still the removal it intended to revert.

The cache therefore retains:

```text
resource:   nil
generation: removal generation
```

while rollback state may still need that information.

The cache counts rollback owners for each tombstone. Owners can include:

- caller-owned rollback;
- staged response rollback;
- published-but-unsent rollback;
- rollback attached to an outstanding response.

Ownership is stored inside the node state in fixed TypeURL slots. Each occupied
slot contains only `(resource name, generation)` counters for that resource
type, avoiding repeated node and TypeURL values in the ownership keys.

Once the final owner terminates, the tombstone is removed. If that leaves a resource map empty, the map can return to `nil`.

## No-op updates

A semantic no-op does not allocate a new generation and does not create rollback state.

If the caller supplied a WaitGroup, the cache checks the specific affected resource against accepted and pending state.

A typed single-resource wait is tagged with the generation stored on that
resource entry, rather than the node-wide snapshot generation. For a generic
sparse mutation, the cache uses the newest generation among the named resources
for each TypeURL, falling back to the staged or published snapshot generation
when the mutation names no resource of that type. Consequently, an unrelated
resource update cannot prevent an older response containing the matching
resource state from resolving the wait.

The no-op can then:

- complete immediately if the resource is already ACKed;
- attach to an in-flight response containing that resource state;
- fail immediately if that exact state was NACKed;
- wait for a staged state to be published and acknowledged.

This is resource-specific.

For example, if `listener1` is unchanged and already ACKed, its no-op update completes immediately even if an unrelated update to `listener2` is awaiting an ACK for the same Listener TypeURL.

## Startup before Envoy connects

The agent can create desired resources before Envoy establishes its first watch.

These mutations:

- update cache-private desired state;
- remain staged;
- coalesce rollback by resource name;
- do not generate a snapshot for every mutation.

For resources created after agent restart, the rollback target is simply “resource absent.” The initial rollback state therefore retains no old protobufs for those resources.

When Envoy eventually connects, the first relevant watch causes the staged state to be finalized and delivered.

If a new ADS stream NACKs its initial Listener synchronization, the cache does
not remove the desired resources. Instead, LDS on that stream enters a one-shot
soft reset:

1. The NACKed response keeps its completions and response-owned rollback state.
2. Only the LDS watch is rebound to a stream-private empty snapshot.
3. The empty response uses a reset-only version and does not accept, reject, or
   otherwise alter desired cache generations.
4. Once the empty LDS response has been ACKed, the LDS watch is rebound to the
   authoritative cache.
5. Its next Listener response contains the cache contents current at that time,
   including mutations accumulated while the reset was in progress.

RDS, CDS/EDS, SDS, NPDS, and NPHDS remain attached to the authoritative cache
throughout the reset. Draining listeners and their existing connections may
still depend on routes, clusters, endpoints, TLS secrets, and policy resources;
withdrawing those resources would turn listener recovery into a traffic
disruption. A non-LDS initial NACK therefore follows the ordinary
generation-aware rollback path rather than initiating a soft reset.

The empty snapshot is therefore a transport synchronization barrier, not
desired state. It is stored under a synthetic stream-specific node ID and is
never installed as the node's published snapshot. Reset watches also do not
count as capacity to consume staged desired changes, so cache mutation and
coalescing continue normally during the reset.

No initial snapshot is retained for replay. Returning the stream to the live
cache for LDS lets ordinary lazy finalization publish the newest desired state.
An ACK of that state resolves all represented generations. A NACK after the
empty barrier uses normal generation-aware rollback because stale Envoy state
has already been eliminated as the cause.

An LDS soft reset is attempted at most once per ADS stream. A NACK of its empty
reset response closes the stream without modifying desired state.

## ADS stream disconnect

Rollback state belongs to the node and resource generations, not to one ADS stream. It is therefore not discarded merely because a stream disconnects.

`CompletionCallbacks` owns one stream registry keyed by xDS mode and stream ID.
After a SotW stream's first request identifies its node, a construction-time
`StreamLifecycleHandler` notifies the cache of the stream start and close.
Keeping the mode in the key and fixed cache slots prevents future protocol
modes with independently allocated stream IDs from colliding.

`nodeState` mirrors active stream IDs in fixed mode slots. The cache tracks
individual SotW one-response watches in a common index by node, protocol mode,
and TypeURL. Streams retain node state across one-response watch replacement,
while the watch index identifies which resource types can consume a response
immediately.

Backend responses are relayed through cache-owned buffered channels.
While holding the cache lock, response collection associates the response with
its exact request, claims its response-owned rollback, and removes that watch
from the common index. The response is delivered to go-control-plane only after
the lock is released.

When the last ADS stream for a node closes:

- the node’s desired state remains;
- staged mutations remain;
- published snapshots remain;
- pending completions remain;
- response-owned rollback state remains;
- open watches belonging to the old stream are canceled;
- the old pending nonce, stream ID, and response association are cleared;
- the remembered accepted snapshot is cleared.
- any stream-private soft-reset snapshot is discarded.

The negotiated node epoch is retained across a stream gap whenever desired,
staged, or rollback state still owns the node. If none of those remain, the
empty node state and its published empty snapshot are removed; a later stream
can safely negotiate a new epoch because no state from the old namespace
remains owned by the cache.

Clearing accepted state is necessary because a new stream may belong to a newly restarted Envoy process that has no resources.

An ACK or NACK referring to the old stream or nonce cannot affect state after the disconnect.

If another stream for the same node remains open, the node-wide protocol state is not cleared merely because one stream closed.

## Rollback states across disconnect

Different rollback stages behave as follows.

### Staged but unpublished rollback

It remains staged.

Further Cilium mutations while Envoy is disconnected are merged into the same sparse staged rollback state.

No snapshot is generated until a relevant watch is available.

### Published but unsent rollback

It remains registered as unsent rollback for that node and TypeURL.

A later watch can consume the published state, or a newer publication can coalesce additional history while no response has claimed it.

### Sent but unacknowledged rollback

It remains pending after the stream closes.

Its association with the dead stream and nonce is cleared, but its resource rollback state is retained. A later response on a new stream can represent those generations again.

This is conservative: disconnect does not prove whether Envoy applied the response before the connection disappeared.

## ADS stream reconnection

When Envoy reconnects using the same node ID, its first DiscoveryRequest establishes the new stream identity.

The new watch can then consume the current state.

The first supported requests received by a new cache instance negotiate the
node epoch as described above. Since the selected epoch differs from every
recognized epoch reported by a previously unseen TypeURL, go-control-plane
cannot suppress the new agent's initial state merely because its generation
number overlaps a generation retained by Envoy.

### Fresh Envoy with no version

If the request has no current version, it is treated as a fresh subscription.

The cache:

1. Finalizes relevant staged state if necessary.
2. Delivers the current published snapshot.
3. Associates pending mutation generations with the new response.
4. Waits for an ACK or NACK using the new stream and nonce.

### Envoy reports the current published version

Envoy may reconnect to the same running agent and report that it already has
the current generation version.

If the reported version matches the current published snapshot, the cache can treat the corresponding snapshot generation as accepted without requiring another response.

Pending response rollback represented by that generation is finalized and released.

### Envoy reports an older version

If Envoy reports an older version, the current snapshot is delivered again.

The response on the new stream adopts the pending generations represented by that snapshot. Its eventual ACK or NACK resolves their rollback state.

## Reconnection example

Consider:

```text
generation 40: P0 → P1
response containing P1 is sent
ADS stream disconnects before ACK
generation 41: P1 → P2 while disconnected
Envoy reconnects
```

The generation-40 response rollback is retained. The generation-41 update is staged separately because generation 40 had already been represented by a response.

On reconnection, the new response contains the current desired state `P2`. Both earlier generations can be associated with that new response.

If Envoy ACKs it:

- rollback for both generations is finalized;
- retained old resources and tombstones are released.

If Envoy NACKs it:

- rollback is processed newest-first;
- generation fencing restores the correct pre-response state;
- resources superseded by still-newer changes are left untouched.

## Nodes with no desired resources

An open ADS stream with a known node ID creates `nodeState` even when its
desired state is empty. This lets the stream negotiate an epoch which remains
stable across its TypeURL requests. Open-watch bookkeeping remains separate
from desired node state because an individual watch is consumed for every
response while the stream continues to exist.

The node state remains while it has any desired resources, staged mutations,
rollback ownership, or open streams. It is removed only when all those owners
are gone. Resource maps must be completely empty for removal: nil-resource
tombstones still protect possible NACK rollback and therefore count as state.

Desired node state is not removed simply because the node disconnects. Desired
resources belong to Cilium configuration, not connection lifetime. Conversely,
an empty node state is removed after its final stream closes, so a later stream
can negotiate a fresh epoch without leaving per-node protocol state behind.

## Memory behavior while disconnected

Caller-owned rollback is released when each caller finalizes or reverts its
`Revertible`, even if Envoy is disconnected.

Response rollback remains because a future Envoy response may still ACK or NACK the affected state.

While there is no consumable watch:

- repeated mutations are coalesced;
- rollback grows with distinct affected resources, not mutation count;
- repeated updates to the same resource retain one oldest previous value and one newest expected generation;
- initial resource creation retains an absence marker rather than a previous protobuf;
- no snapshot or full-cache copy is generated per mutation.

The last unacknowledged response rollback may remain indefinitely if the node never reconnects. This is intentional conservative retention and is bounded by the resources represented by the outstanding state.

A less common case can retain more than one response-owned lifecycle: repeated connect → response → disconnect cycles with new mutations between responses and no intervening ACK or NACK. A later response associates those pending lifecycles with its generation, and its eventual ACK or NACK resolves them together. They are not discarded merely because the previous stream disappeared.

## Listener-derived policy waits

The ADS server supplies a ListenerObserver when constructing the cache. The ADS-owned observer counts desired listeners which start an NPDS client, updating its count from committed Listener transitions, including cache-owned NACK reverts. Both observer methods run under the cache lock and neither takes the ADS server mutex or calls back into the cache. A bulk replacement applies its net change under one cache lock and cannot expose a transient zero count.

`UpsertNetworkPolicy` asks the observer whether the node has NPDS listeners under the same lock used to register its ACK wait. If not, the policy is still staged but the caller callback completes successfully without waiting for Envoy. When the count falls from positive to zero, the observer returns true and the cache detaches that node's already-registered NPDS caller waits before releasing its lock; the cache completes them successfully after unlocking. A policy update cannot slip between the removal and detachment; a later listener addition and policy update cannot be mistaken for an older wait, even if the policy's resource generation is old.

This success releases only the caller's ACK wait. It does not mark the snapshot as ACKed, finalize the caller-owned rollback, or discard response-owned NACK rollback state. Envoy can still NACK an already-sent response, and a broader endpoint regeneration failure can still invoke its returned rollback.

## Main invariants

The design relies on the following invariants:

1. Desired protobuf resources are immutable once stored.
2. Every real mutation receives a generation.
3. Every resource name records the generation that last changed it.
4. Rollback state is sparse and contains only affected resources.
5. A rollback changes a resource only if its expected generation still matches.
6. Caller-owned and response-owned rollback have independent lifetimes.
7. Caller timeout or finalization cannot disable a later NACK rollback.
8. ACK or NACK of an old response cannot overwrite a newer resource generation.
9. Response rollback is scoped to the rejected TypeURL.
10. Staged and unsent rollback is coalesced by TypeURL and resource name.
11. Removal tombstones exist only while some rollback lifecycle requires them.
12. Stream disconnect clears protocol association, not desired or rollback state.
13. Reconnection using the same node ID can adopt and resolve retained generations.
14. Repeated finalization or reversion of one lifecycle warns and otherwise does nothing.

The result is rollback management that remains correct across coalesced updates, asynchronous caller completion, delayed ACKs and NACKs, resource deletion and recreation, agent startup, and ADS stream reconnection—without retaining a complete snapshot for every cache mutation.
