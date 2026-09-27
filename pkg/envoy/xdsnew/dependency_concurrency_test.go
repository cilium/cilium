// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	status "google.golang.org/genproto/googleapis/rpc/status"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestDependentRegistrationBeforeNACKCacheLock(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			c, handler := newGatedNACKCache(t, strict)
			t.Cleanup(func() { c.completionCbs.OnStreamClosed(1, nil) })
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			t.Cleanup(cancel)
			const nodeID = "coverage-node"
			a := &cluster.Cluster{Name: "a"}
			require.NoError(t, c.ApplyResource(ctx, nodeID, typeurl.Cluster, "a", a, nil, nil))
			cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
			response := cds.receive(t)
			gate := handler.gate(t, handler.beforeLock)
			nacked := make(chan error, 1)
			go func() {
				nacked <- c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					TypeUrl: typeurl.Cluster.URL(), ResponseNonce: response.Nonce, ErrorDetail: &status.Status{Message: "rejected a"},
				})
			}()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal("NACK did not enter its cache transaction handler")
			}

			// Selection has not acquired the cache lock yet. A concurrent API
			// transaction can still reuse A, so its SDS wait and inverse must join
			// the same CDS NACK. No registration can interleave after selection.
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			result := make(chan error, 1)
			var callbacks TypeURLCallbacks
			callbacks.Set(typeurl.Secret, func(err error) {
				c.GetResource(nodeID, typeurl.Secret, "s1")
				result <- err
			})
			require.NoError(t, c.ApplyResources(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters: map[string]*cluster.Cluster{"a": a}, Secrets: map[string]*tls.Secret{"s1": {Name: "s1"}},
			}}, wg, callbacks))
			requireCoveragePending(t, result)
			gate.unblock()
			select {
			case err := <-nacked:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("NACK did not complete")
			}
			require.ErrorContains(t, wg.Wait(), "rejected a")
			require.ErrorContains(t, <-result, "rejected a")
			require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, "a"))
			require.Nil(t, c.GetResource(nodeID, typeurl.Secret, "s1"))
			require.Zero(t, c.completionCbs.PendingCompletionCount())
		})
	}
}
