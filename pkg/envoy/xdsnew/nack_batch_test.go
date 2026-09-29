// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func nackTestSecret(contents string) *secret.Secret {
	return &secret.Secret{Name: "secret", Type: &secret.Secret_GenericSecret{
		GenericSecret: &secret.GenericSecret{Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: contents}}},
	}}
}

func TestNACKClaimsWaitRegisteredBeforeCacheLock(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, bulk := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/bulk=%t", strict, bulk), func(t *testing.T) {
				c, handler := newGatedNACKCache(t, strict)
				t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil) })
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				t.Cleanup(cancel)
				baseline, a := nackTestSecret("accepted"), nackTestSecret("A")
				s := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", baseline, nil, nil))
				s.reply(t, s.receive(t, "secret"), "", "secret")
				require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", a, nil, nil))
				response := s.receive(t, "secret")
				gate := handler.gate(t, handler.beforeLock)
				result := make(chan error, 1)
				go func() {
					result <- c.completionCbs.OnStreamRequest(s.id, &discovery.DiscoveryRequest{
						TypeUrl: s.typeURL, ResponseNonce: response.Nonce, ResourceNames: []string{"secret"},
						ErrorDetail: &status.Status{Message: "invalid secret"},
					})
				}()
				select {
				case <-gate.entered:
				case <-ctx.Done():
					t.Fatal("NACK did not enter its owner")
				}
				// No inverse or waiter may be claimed before the cache lock. This
				// late no-op wait must be included in the same NACK's selection.
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				done := make(chan error, 1)
				callback := func(err error) {
					c.GetResource("coverage-node", typeurl.Secret, "secret")
					done <- err
				}
				if bulk {
					var callbacks TypeURLCallbacks
					callbacks.Set(typeurl.Secret, callback)
					require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{Upserted: xds.Resources{
						Secrets: map[string]*secret.Secret{"secret": a},
					}}, wg, callbacks))
				} else {
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", a, wg, callback))
				}
				gate.unblock()
				select {
				case err := <-result:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("NACK did not finish")
				}
				s.reply(t, s.receive(t, "secret"), "", "secret")
				require.ErrorContains(t, wg.Wait(), "invalid secret")
				require.ErrorContains(t, <-done, "invalid secret")
			})
		}
	}
}

func TestNACKRevalidatesAfterAcquiringCacheLock(t *testing.T) {
	for _, progress := range []string{"closed", "new-response"} {
		t.Run(progress, func(t *testing.T) {
			c, handler := newGatedNACKCache(t, false)
			t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil) })
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			t.Cleanup(cancel)
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
			a, b := nackTestSecret("A"), nackTestSecret("B")
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", a, nil, nil))
			responseA := s.receive(t, "secret")
			gate := handler.gate(t, handler.beforeLock)
			result := make(chan error, 1)
			go func() {
				result <- c.completionCbs.OnStreamRequest(s.id, &discovery.DiscoveryRequest{
					TypeUrl: s.typeURL, ResponseNonce: responseA.Nonce, ResourceNames: []string{"secret"},
					ErrorDetail: &status.Status{Message: "stale NACK"},
				})
			}()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal("NACK did not enter its owner")
			}
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", b, nil, nil))
			if progress == "closed" {
				c.completionCbs.OnStreamClosed(s.id, nil)
			} else {
				s.receive(t, "secret")
			}
			gate.unblock()
			select {
			case err := <-result:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("NACK did not finish")
			}
			require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "secret"))
		})
	}
}

func TestNACKBatchPublishesOnlyFinalState(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, shape := range []string{"chain", "aba", "absence", "cross-type", "deferred"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, shape), func(t *testing.T) {
				c, _ := newGatedNACKCache(t, strict)
				t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil); c.completionCbs.OnStreamClosed(2, nil) })
				baseline, a, b := nackTestSecret("accepted"), nackTestSecret("A"), nackTestSecret("B")
				first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				second := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
				apply := func(value *secret.Secret) {
					t.Helper()
					mutations := ResourceMutations{Upserted: xds.Resources{Secrets: map[string]*secret.Secret{"secret": value}}}
					if shape == "cross-type" {
						mutations.Upserted.Clusters = map[string]*cluster.Cluster{
							"sibling": {Name: "sibling", AltStatName: value.GetGenericSecret().GetSecret().GetInlineString()},
						}
					}
					require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", mutations, nil, TypeURLCallbacks{}))
				}
				if shape == "absence" {
					baseline = nil
				} else {
					apply(baseline)
					first.reply(t, first.receive(t, "secret"), "", "secret")
				}
				apply(a)
				responseA := first.receive(t, "secret")
				if shape == "aba" {
					b = baseline
				}
				apply(b)
				responseB := second.receive(t, "secret")
				before := c.getNodeState("coverage-node").resourceGeneration
				published := mustSnapshot(t, c, "coverage-node")

				// A watch ready before recovery would observe the intermediate A
				// with per-lifecycle publication. It must receive only the final baseline.
				responses := make(chan cache.Response, 2)
				request := &cache.Request{
					Node: &core.Node{Id: "coverage-node"}, TypeUrl: second.typeURL,
					ResourceNames: []string{"secret"}, VersionInfo: responseB.VersionInfo,
				}
				if shape != "deferred" {
					cancel, err := c.CreateWatch(request, second.sub, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
				}
				second.reply(t, responseB, "invalid secret", "secret")
				require.Equal(t, before+1, c.getNodeState("coverage-node").resourceGeneration, "one corrective generation for the whole batch")
				if baseline == nil {
					require.Nil(t, c.GetResource("coverage-node", typeurl.Secret, "secret"))
				} else {
					require.Same(t, baseline, c.GetResource("coverage-node", typeurl.Secret, "secret"))
				}
				if shape == "cross-type" {
					require.Equal(t, "accepted", c.GetResource("coverage-node", typeurl.Cluster, "sibling").(*cluster.Cluster).AltStatName)
				}
				if shape == "deferred" {
					// Recovery must commit without a ready watch, consume the selected
					// inverses, and leave the previous published snapshot untouched.
					require.Same(t, published, mustSnapshot(t, c, "coverage-node"))
					require.Empty(t, responses)
					require.True(t, c.getNodeState("coverage-node").rollbacks.responses.Empty())
				}
				var wg *completion.WaitGroup
				var done chan error
				if baseline != nil {
					wg = completion.NewWaitGroup(t.Context())
					t.Cleanup(wg.Cancel)
					done = make(chan error, 1)
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Secret, "secret", baseline, wg, func(err error) {
						// Completion callbacks must run after the cache lock is released.
						c.GetResource("coverage-node", typeurl.Secret, "secret")
						done <- err
					}))
					requireCoveragePending(t, done)
					first.reply(t, responseA, "", "secret")
					second.reply(t, responseB, "", "secret")
					requireCoveragePending(t, done)
				}
				if shape == "deferred" {
					cancel, err := c.CreateWatch(request, second.sub, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
				}
				require.Len(t, responses, 1)
				correction := second.deliver(t, <-responses)
				if baseline == nil {
					require.Empty(t, correction.Resources)
				} else {
					require.Len(t, correction.Resources, 1)
					value := &secret.Secret{}
					require.NoError(t, correction.Resources[0].UnmarshalTo(value))
					require.Equal(t, "accepted", value.GetGenericSecret().GetSecret().GetInlineString())
					second.reply(t, correction, "", "secret")
					require.NoError(t, wg.Wait())
					require.NoError(t, <-done)
				}
			})
		}
	}
}

func TestNACKBatchSerializesCacheCallers(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, operation := range []string{"read", "no-op", "newer", "caller-revert"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, operation), func(t *testing.T) {
				c, handler := newGatedNACKCache(t, strict)
				t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil) })
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				t.Cleanup(cancel)
				baseline, a, b := nackTestSecret("accepted"), nackTestSecret("A"), nackTestSecret("B")
				s := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", baseline, nil, nil))
				s.reply(t, s.receive(t, "secret"), "", "secret")
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				caller, err := c.ApplyResourceWithRollback(ctx, "coverage-node", typeurl.Secret, "secret", a, wg, nil)
				require.NoError(t, err)
				t.Cleanup(func() {
					if operation != "caller-revert" {
						caller.Finalize()
					}
				})
				response := s.receive(t, "secret")
				gate := handler.gate(t, handler.beforeRevert)
				result := make(chan error, 1)
				go func() {
					result <- c.completionCbs.OnStreamRequest(s.id, &discovery.DiscoveryRequest{
						TypeUrl: s.typeURL, ResponseNonce: response.Nonce, ResourceNames: []string{"secret"},
						ErrorDetail: &status.Status{Message: "invalid secret"},
					})
				}()
				select {
				case <-gate.entered:
				case <-ctx.Done():
					t.Fatal("NACK did not enter its cache transaction")
				}
				started, finished := make(chan struct{}), make(chan error, 1)
				go func() {
					close(started)
					switch operation {
					case "read":
						if c.GetResource("coverage-node", typeurl.Secret, "secret") != baseline {
							finished <- errors.New("read observed the rejected value")
							return
						}
						finished <- nil
					case "caller-revert":
						finished <- caller.Revert()
					default:
						value := b
						if operation == "no-op" {
							value = a
						}
						finished <- c.ApplyResource(ctx, "coverage-node", typeurl.Secret, "secret", value, nil, nil)
					}
				}()
				<-started
				select {
				case err := <-finished:
					t.Fatalf("cache operation interleaved with recovery: %v", err)
				case <-time.After(10 * time.Millisecond):
				}
				gate.unblock()
				select {
				case err := <-result:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("NACK did not finish")
				}
				select {
				case err := <-finished:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("cache caller did not resume")
				}
				require.ErrorContains(t, wg.Wait(), "invalid secret")
				if operation == "newer" {
					require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "secret"))
				} else if operation == "no-op" {
					// It was a no-op only before recovery. Once serialized after it,
					// this is a new API transaction and must remain eligible for ACK.
					require.Same(t, a, c.GetResource("coverage-node", typeurl.Secret, "secret"))
				}
			})
		}
	}
}

func TestFailedNACKBatchRetainsAllInverses(t *testing.T) {
	c := newCoverageCache(t)
	baseline, a, b := nackTestSecret("accepted"), nackTestSecret("A"), nackTestSecret("B")
	first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
	second := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
	for _, value := range []*secret.Secret{baseline, a, b} {
		require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Secret, "secret", value, nil, nil))
		if value == baseline {
			first.reply(t, first.receive(t, "secret"), "", "secret")
		} else if value == a {
			first.receive(t, "secret")
		}
	}
	response := second.receive(t, "secret")
	before := c.getNodeState("coverage-node").resourceGeneration
	backend := c.SnapshotCache
	failure := errors.New("corrective publication failed")
	failed := newMockSnapshotCache()
	failed.snapshots["coverage-node"] = mustSnapshot(t, c, "coverage-node")
	failed.setSnapshotErr = failure
	c.SnapshotCache = failed
	// Recovery finalizes synchronously only if an open watch can consume the
	// correction. The mock retains this watch without sending a response.
	cancelWatch, err := c.CreateWatch(&cache.Request{
		Node: &core.Node{Id: "coverage-node"}, TypeUrl: second.typeURL,
		ResourceNames: []string{"secret"}, VersionInfo: response.VersionInfo,
	}, second.sub, make(chan cache.Response, 1))
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	require.ErrorIs(t, c.completionCbs.OnStreamRequest(second.id, &discovery.DiscoveryRequest{
		TypeUrl: second.typeURL, ResponseNonce: response.Nonce, ResourceNames: []string{"secret"},
		ErrorDetail: &status.Status{Message: "invalid secret"},
	}), failure)
	require.Same(t, b, c.GetResource("coverage-node", typeurl.Secret, "secret"), "failed publication must not leave a partial rollback to A")
	require.Equal(t, before, c.getNodeState("coverage-node").resourceGeneration)
	require.Equal(t, 2, c.getNodeState("coverage-node").rollbacks.responses.Len())
	c.SnapshotCache = backend
	c.completionCbs.OnStreamClosed(second.id, nil)
	third := coverageStream{cache: c, id: 3, typeURL: typeurl.Secret.URL()}
	t.Cleanup(func() { c.completionCbs.OnStreamClosed(third.id, nil) })
	third.reply(t, third.receive(t, "secret"), "invalid secret", "secret")
	require.Same(t, baseline, c.GetResource("coverage-node", typeurl.Secret, "secret"))
	require.True(t, c.getNodeState("coverage-node").rollbacks.responses.Empty())
}
