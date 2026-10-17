// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type nackGate struct {
	entered chan struct{}
	release chan struct{}
}

func (gate *nackGate) pause() {
	close(gate.entered)
	<-gate.release
}

func (gate *nackGate) unblock() {
	select {
	case <-gate.release:
	default:
		close(gate.release)
	}
}

// Gates wrap the real transaction boundary, never individual inverses. They
// either delay entry before selection or pause recovery with the cache locked.
type gatedNACKHandler struct {
	cache        *cacheImpl
	beforeLock   chan *nackGate
	beforeRevert chan *nackGate
}

func (handler *gatedNACKHandler) StreamStarted(streamID int64, nodeID string, mode callbacks.StreamMode) {
	handler.cache.StreamStarted(streamID, nodeID, mode)
}

func (handler *gatedNACKHandler) StreamClosed(streamID int64, nodeID string, mode callbacks.StreamMode) {
	handler.cache.StreamClosed(streamID, nodeID, mode)
}

func newGatedNACKCache(t *testing.T) (*cacheImpl, *gatedNACKHandler) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	c := newCache(logger, WithNodeIDs("coverage-node"))
	handler := &gatedNACKHandler{cache: c, beforeLock: make(chan *nackGate, 2), beforeRevert: make(chan *nackGate, 2)}
	c.completionCbs = callbacks.NewCompletionCallbacks(logger, handler)
	return c, handler
}

func (handler *gatedNACKHandler) gate(t *testing.T, queue chan *nackGate) *nackGate {
	t.Helper()
	gate := &nackGate{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(gate.unblock)
	queue <- gate
	return gate
}

func (handler *gatedNACKHandler) HandleNACK(nodeID string, process func(callbacks.RevertBatch) error) error {
	select {
	case gate := <-handler.beforeLock:
		gate.pause()
	default:
	}
	return handler.cache.HandleNACK(nodeID, func(revert callbacks.RevertBatch) error {
		return process(func(rollbacks []Rollback) error {
			select {
			case gate := <-handler.beforeRevert:
				gate.pause()
			default:
			}
			return revert(rollbacks)
		})
	})
}

func TestNACKRecoveryCannotRestoreRejectedPredecessor(t *testing.T) {
	for _, order := range []string{
		"sequential", "overlap-older-first", "overlap-newer-first", "caller-after-nack",
		"unsent", "caller-after-ack", "newer-after-nacks", "prior-absence",
	} {
		t.Run(order, func(t *testing.T) {
			c, handler := newGatedNACKCache(t)
			t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil); c.completionCbs.OnStreamClosed(2, nil) })
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			t.Cleanup(cancel)
			value := func(contents string) *secret.Secret {
				return &secret.Secret{Name: "secret", Type: &secret.Secret_GenericSecret{
					GenericSecret: &secret.GenericSecret{Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: contents}}},
				}}
			}
			baseline, a, b := value("accepted"), value("A"), value("B")
			first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
			second := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
			if order == "prior-absence" {
				baseline = nil
			} else {
				require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", baseline, nil, nil))
				first.reply(t, first.receive(t, "secret"), "", "secret")
			}
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", a, nil, nil))
			responseA := first.receive(t, "secret")
			callerB, err := c.ApplyResourceWithRollback(ctx, "coverage-node", typeurl.Secret, "secret", b, nil, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				if callerB != nil {
					callerB.Finalize()
				}
			})
			var responseB *discovery.DiscoveryResponse
			if order != "unsent" {
				responseB = second.receive(t, "secret")
			}
			nack := func(id int64, response *discovery.DiscoveryResponse) error {
				return c.completionCbs.OnStreamRequest(id, &discovery.DiscoveryRequest{
					TypeUrl: typeurl.Secret.URL(), ResponseNonce: response.Nonce, ResourceNames: []string{"secret"},
					ErrorDetail: &status.Status{Message: "invalid secret"},
				})
			}
			if order == "overlap-older-first" || order == "overlap-newer-first" {
				gateA, gateB := handler.gate(t, handler.beforeLock), handler.gate(t, handler.beforeLock)
				resultA, resultB := make(chan error, 1), make(chan error, 1)
				await := func(entered <-chan struct{}) {
					t.Helper()
					select {
					case <-entered:
					case <-ctx.Done():
						t.Fatal("NACK did not reach the cache transaction boundary")
					}
				}
				finish := func(gate *nackGate, result <-chan error) {
					t.Helper()
					gate.unblock()
					select {
					case err := <-result:
						require.NoError(t, err)
					case <-ctx.Done():
						t.Fatal("NACK recovery did not finish")
					}
				}
				go func() { resultA <- nack(1, responseA) }()
				await(gateA.entered)
				go func() { resultB <- nack(2, responseB) }()
				await(gateB.entered)
				if order == "overlap-older-first" {
					finish(gateA, resultA)
					finish(gateB, resultB)
				} else {
					finish(gateB, resultB)
					finish(gateA, resultA)
				}
			} else {
				var newest *secret.Secret
				if order == "newer-after-nacks" {
					newest = value("C")
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", newest, nil, nil))
				}
				require.NoError(t, nack(1, responseA))
				if order == "unsent" {
					// B is still desired, but its unsent inverse must now
					// bypass A before the next watch claims that inverse.
					require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "secret"))
					responseB = second.receive(t, "secret")
				}
				if order == "caller-after-ack" {
					second.reply(t, responseB, "", "secret")
					require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "secret"), "A's NACK must not remove accepted B")
				}
				if order == "caller-after-nack" || order == "caller-after-ack" {
					require.NoError(t, callerB.Revert())
					callerB = nil
				} else {
					require.NoError(t, nack(2, responseB))
				}
				if newest != nil {
					require.Same(t, newest, c.GetResource("coverage-node", typeurl.Secret, "secret"), "old NACKs must not remove independent C")
					require.NoError(t, nack(2, second.receive(t, "secret")))
				}
			}
			if baseline == nil {
				require.Nil(t, c.GetResource("coverage-node", typeurl.Secret, "secret"))
			} else {
				require.Same(t, baseline, c.GetResource("coverage-node", typeurl.Secret, "secret"),
					"a later rollback must not resurrect the rejected A, even after its handler consumed A's inverse")
				// The correction is a fresh publication. Its ACK, not a stale
				// response for A or B, must establish acceptance for no-op waits.
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				done := make(chan error, 1)
				require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", baseline, wg,
					func(err error) { done <- err }))
				requireCoveragePending(t, done)
				if order == "caller-after-nack" {
					second.reply(t, responseB, "", "secret")
					requireCoveragePending(t, done)
				}
				first.reply(t, first.receive(t, "secret"), "", "secret")
				require.NoError(t, wg.Wait())
				require.NoError(t, <-done)
			}
		})
	}

}

func TestNACKRecoveryRebasesOnlyRejectedNames(t *testing.T) {
	for _, crossType := range []bool{false, true} {
		shape := "same-type"
		if crossType {
			shape = "cross-type"
		}
		for _, outcome := range []string{"nack", "unsent-nack", "caller-after-ack"} {
			t.Run(shape+"/"+outcome, func(t *testing.T) {
				c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("coverage-node"))
				t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil); c.completionCbs.OnStreamClosed(2, nil) })
				transaction := func(contents string) ResourceMutations {
					mutations := ResourceMutations{Upserted: xds.Resources{Secrets: map[string]*secret.Secret{
						"triggering-change": {Name: "triggering-change", Type: &secret.Secret_GenericSecret{GenericSecret: &secret.GenericSecret{
							Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: contents}},
						}}},
						"sibling": {Name: "sibling", Type: &secret.Secret_GenericSecret{GenericSecret: &secret.GenericSecret{
							Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: contents}},
						}}},
					}}}
					if crossType {
						delete(mutations.Upserted.Secrets, "sibling")
						mutations.Upserted.Clusters = map[string]*cluster.Cluster{
							"sibling": {Name: "sibling", AltStatName: contents},
						}
					}
					return mutations
				}
				baseline := transaction("accepted")
				first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				second := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
				if crossType {
					second.typeURL = typeurl.Cluster.URL()
				}
				firstNames, secondNames := []string{"triggering-change"}, []string{"sibling"}
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", baseline, nil, typeurl.Set{}))
				first.reply(t, first.receive(t, firstNames...), "", firstNames...)
				second.reply(t, second.receive(t, secondNames...), "", secondNames...)
				require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", transaction("A"), nil, typeurl.Set{}))
				responseA := first.receive(t, firstNames...)
				updated := transaction("B")
				callerB, err := c.ApplyResourcesWithRollback(t.Context(), "coverage-node", updated, nil, typeurl.Set{})
				require.NoError(t, err)
				t.Cleanup(func() {
					if callerB != nil {
						callerB.Finalize()
					}
				})
				var responseB *discovery.DiscoveryResponse
				if outcome != "unsent-nack" {
					responseB = second.receive(t, secondNames...)
				}
				first.reply(t, responseA, "invalid resource", firstNames...)
				if outcome == "unsent-nack" {
					// B's pending rollback must bypass the rejected value even
					// before B has been published or claimed by a response.
					responseB = second.receive(t, secondNames...)
				}

				if outcome == "caller-after-ack" {
					second.reply(t, responseB, "", secondNames...)
					require.NoError(t, callerB.Revert())
					callerB = nil
				} else {
					second.reply(t, responseB, "invalid resource", secondNames...)
				}
				// Rejecting A's triggering change rebases B's rollback for that name
				// without reverting B. The sibling's A was never rejected. Caller
				// rollback still restores both names, each to its own baseline.
				wantChange := updated.Upserted.Secrets["triggering-change"]
				wantSibling := baseline
				if outcome == "caller-after-ack" {
					wantChange = baseline.Upserted.Secrets["triggering-change"]
					wantSibling = transaction("A")
				}
				require.True(t, proto.Equal(wantChange, c.GetResource("coverage-node", typeurl.Secret, "triggering-change")))
				if crossType {
					require.True(t, proto.Equal(wantSibling.Upserted.Clusters["sibling"], c.GetResource("coverage-node", typeurl.Cluster, "sibling")))
				} else {
					require.True(t, proto.Equal(wantSibling.Upserted.Secrets["sibling"], c.GetResource("coverage-node", typeurl.Secret, "sibling")))
				}
				if callerB != nil {
					callerB.Finalize()
					callerB = nil
				}
				// Caller terminal resolution releases its rollback state.
				// Response ownership is independently released by the ACK.
				first.reply(t, first.receive(t, firstNames...), "", firstNames...)
				second.reply(t, second.receive(t, secondNames...), "", secondNames...)
				c.mutex.Lock()
				state := c.getNodeState("coverage-node")
				emptyCallers, emptyResponses := state.rollbacks.callers.Empty(), state.rollbacks.responses.Empty()
				c.mutex.Unlock()
				require.True(t, emptyCallers)
				require.True(t, emptyResponses)
			})
		}
	}

}

func TestFailedNACKRecoveryCannotRestoreRejectedPredecessor(t *testing.T) {
	c := newCoverageCache(t)
	first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
	baseline := &secret.Secret{Name: "triggering-change"}
	baselineSibling := &secret.Secret{Name: "sibling"}
	apply := func(changed, sibling *secret.Secret) {
		t.Helper()
		require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{Upserted: xds.Resources{
			Secrets: map[string]*secret.Secret{"triggering-change": changed, "sibling": sibling},
		}}, nil, typeurl.Set{}))
	}
	apply(baseline, baselineSibling)
	first.reply(t, first.receive(t, "triggering-change", "sibling"), "", "triggering-change", "sibling")
	a, aSibling := &secret.Secret{Name: "triggering-change", Type: &secret.Secret_GenericSecret{GenericSecret: &secret.GenericSecret{}}},
		&secret.Secret{Name: "sibling", Type: &secret.Secret_GenericSecret{GenericSecret: &secret.GenericSecret{}}}
	apply(a, aSibling)
	responseA := first.receive(t, "triggering-change", "sibling")
	b := &secret.Secret{Name: "triggering-change", Type: &secret.Secret_TlsCertificate{TlsCertificate: &secret.TlsCertificate{}}}
	callerB, err := c.ApplyResourceWithRollback(t.Context(), "coverage-node", typeurl.Secret, "triggering-change", b, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if callerB != nil {
			callerB.Finalize()
		}
	})
	second := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
	responseB := second.receive(t, "triggering-change", "sibling")
	failed := newMockSnapshotCache()
	failed.snapshots["coverage-node"] = mustSnapshot(t, c, "coverage-node")
	failure := errors.New("corrective publication failed")
	failed.setSnapshotErr = failure
	restore := c.replaceSnapshotCache(t, failed)
	// Keep a watch available so recovery exercises response delivery as well
	// as snapshot installation failure.
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Secret.URL(),
		ResourceNames: []string{"triggering-change", "sibling"}, VersionInfo: responseB.VersionInfo,
	}, second.sub, make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.ErrorIs(t, c.completionCbs.OnStreamRequest(first.id, &discovery.DiscoveryRequest{
		TypeUrl: typeurl.Secret.URL(), ResponseNonce: responseA.Nonce,
		ResourceNames: []string{"triggering-change", "sibling"}, ErrorDetail: &status.Status{Message: "invalid secret"},
	}), failure)
	restore()
	// Failed recovery retains A's own inverse for retry. But rejection is
	// definitive: B's caller rollback must bypass A even after that failure.
	require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "triggering-change"))
	require.Same(t, aSibling, c.GetResource("coverage-node", typeurl.Secret, "sibling"))
	require.NoError(t, callerB.Revert())
	callerB = nil
	require.Same(t, baseline, c.GetResource("coverage-node", typeurl.Secret, "triggering-change"))
	require.Same(t, aSibling, c.GetResource("coverage-node", typeurl.Secret, "sibling"))
	// The next NACK retries A's still-current sibling through the retained
	// response-owned recovery. Rebasing B did not consume that recovery state.
	first.reply(t, first.receive(t, "triggering-change", "sibling"), "invalid secret", "triggering-change", "sibling")
	require.Same(t, baseline, c.GetResource("coverage-node", typeurl.Secret, "triggering-change"))
	require.Same(t, baselineSibling, c.GetResource("coverage-node", typeurl.Secret, "sibling"))
}
