// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"log/slog"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestResourceCompletionCallbacksCanReenterCache(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		for _, outcome := range []string{"ack", "nack", "accepted-noop", "pristine-removal"} {
			t.Run(api+"/"+outcome, func(t *testing.T) {
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs("coverage-node")).(*cacheImpl)
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				t.Cleanup(cancel)
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				operationDone := make(chan error, 1)
				t.Cleanup(func() {
					// A lock regression must fail on the timeout, not deadlock again
					// during cleanup. This cache owns no external resources.
					select {
					case <-operationDone:
						c.completionCbs.OnStreamClosed(1, nil)
					default:
					}
				})

				s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
				receive := func() *discovery.DiscoveryResponse {
					request := &discovery.DiscoveryRequest{
						Node: &core.Node{Id: "coverage-node"}, TypeUrl: s.typeURL, VersionInfo: s.version,
					}
					require.NoError(t, c.completionCbs.OnStreamRequest(s.id, request))
					s.sub = stream.NewSotwSubscription(nil, true)
					responses := make(chan cache.Response, 1)
					cancelWatch, err := c.CreateWatch(request, s.sub, responses)
					require.NoError(t, err)
					// Cancel before running the callback under test so a deadlock
					// cannot leave a lock-taking watch cancellation in test cleanup.
					cancelWatch()
					select {
					case response := <-responses:
						return s.deliver(t, response)
					default:
						t.Fatal("expected immediate response")
						return nil
					}
				}
				original := &listener.Listener{Name: "target", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
				var candidate, expected proto.Message
				if outcome != "pristine-removal" {
					require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "target", original, nil, nil))
					s.reply(t, receive(), "")
					candidate = &listener.Listener{Name: "target", PerConnectionBufferLimitBytes: wrapperspb.UInt32(2)}
					expected = candidate
					if outcome == "nack" || outcome == "accepted-noop" {
						expected = original
					}
					if outcome == "accepted-noop" {
						candidate = proto.Clone(original)
					}
				}

				type callbackResult struct {
					cause, mutationError error
					observed             proto.Message
				}
				done := make(chan callbackResult, 2)
				callback := func(cause error) {
					observed := c.GetResource("coverage-node", typeurl.Listener, "target")
					// Exercise both locks as well as read and write reentry. On NACK,
					// this must observe the restored state, not the rejected resource.
					c.completionCbs.PendingCompletionCount()
					mutationErr := c.ApplyResource(ctx, "coverage-node", typeurl.Endpoint, "callback-single",
						&endpoint.ClusterLoadAssignment{ClusterName: "callback-single"}, nil, nil)
					if mutationErr == nil {
						mutationErr = c.ApplyResources(ctx, "coverage-node", ResourceMutations{
							Upserted: xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{
								"callback-bulk": {ClusterName: "callback-bulk"},
							}},
						}, nil, TypeURLCallbacks{})
					}
					done <- callbackResult{cause: cause, mutationError: mutationErr, observed: observed}
				}
				apply := func() error {
					if api == "single" {
						return c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "target", candidate, wg, callback)
					}
					var waits TypeURLCallbacks
					waits.Set(typeurl.Listener, callback)
					return c.ApplyResources(ctx, "coverage-node", ResourceMutations{
						Upserted: xds.Resources{Listeners: map[string]*listener.Listener{"target": typedResource[*listener.Listener](candidate)}},
					}, wg, waits)
				}
				trigger := apply
				if outcome == "ack" || outcome == "nack" {
					require.NoError(t, apply())
					require.Empty(t, done, "callback must wait for the response outcome")
					response := receive()
					request := &discovery.DiscoveryRequest{
						TypeUrl: s.typeURL, VersionInfo: response.VersionInfo, ResponseNonce: response.Nonce,
					}
					if outcome == "nack" {
						request.VersionInfo = ""
						request.ErrorDetail = &status.Status{Message: "invalid target"}
					}
					trigger = func() error { return c.completionCbs.OnStreamRequest(s.id, request) }
				}
				go func() {
					operationDone <- trigger()
					close(operationDone)
				}()
				select {
				case err := <-operationDone:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("completion callback deadlocked while reentering cache APIs")
				}
				require.Len(t, done, 1, "callback must run exactly once")
				result := <-done
				require.NoError(t, result.mutationError)
				if expected != nil {
					require.Same(t, expected, result.observed)
				} else {
					require.Nil(t, result.observed)
				}
				if outcome == "nack" {
					require.ErrorContains(t, result.cause, "invalid target")
					require.ErrorContains(t, wg.Wait(), "invalid target")
				} else {
					require.NoError(t, result.cause)
					require.NoError(t, wg.Wait())
				}
				for _, name := range []string{"callback-single", "callback-bulk"} {
					resource := c.GetResource("coverage-node", typeurl.Endpoint, name)
					require.NotNil(t, resource, name)
					require.Equal(t, name, resource.(*endpoint.ClusterLoadAssignment).ClusterName)
				}
				require.Zero(t, c.completionCbs.PendingCompletionCount())
			})
		}
	}
}
