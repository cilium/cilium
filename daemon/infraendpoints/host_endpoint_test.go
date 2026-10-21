// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/promise"
)

type hostStartup struct {
	endpointcreator.EndpointCreator
	endpointmanager.EndpointManager
	endpointstate.Restorer
	created chan struct{}
}

func (*hostStartup) WaitForEndpointRestoreWithoutRegeneration(context.Context) error {
	return nil
}
func (*hostStartup) HostEndpointExists() bool {
	return false
}
func (s *hostStartup) AddHostEndpoint(context.Context) error {
	close(s.created)
	return nil
}

func TestHostEndpointDNSProxyReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	startup := &hostStartup{created: make(chan struct{})}
	restored, restorerPromise := promise.New[endpointstate.Restorer]()
	// Model disabled restoration: the restorer does not delay host creation.
	restored.Resolve(startup)
	resolver, ready := promise.New[bootstrap.DNSProxyInitialized]()
	creator := &hostEndpointCreator{
		logger:                 hivetest.Logger(t),
		endpointCreator:        startup,
		endpointManager:        startup,
		endpointRestorePromise: restorerPromise,
		dnsProxyPromise:        ready,
	}
	health, _ := cell.NewSimpleHealth()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- creator.createHostEndpoint(ctx, health)
	}()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-startup.created:
		t.Fatal("host endpoint created before DNS proxy readiness")
	case err := <-done:
		t.Fatalf("host initialization finished before DNS proxy readiness: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	resolver.Resolve(bootstrap.DNSProxyInitialized{})
	require.NoError(t, <-done)
	select {
	case <-startup.created:
	default:
		t.Fatal("host endpoint was not created after DNS proxy readiness")
	}
}
