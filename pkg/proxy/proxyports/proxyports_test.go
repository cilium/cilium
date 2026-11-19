// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	iptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	util "github.com/cilium/cilium/pkg/envoy/util"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
)

func proxyPortsForTest(t *testing.T) *ProxyPorts {
	fakeIPTablesManager := iptables.NewManager()
	config := ProxyPortsConfig{
		ProxyPortrangeMin:          10000,
		ProxyPortrangeMax:          20000,
		RestoredProxyPortsAgeLimit: 0,
	}

	p := NewProxyPorts(hivetest.Logger(t), config, fakeIPTablesManager)
	p.Trigger = job.NewTrigger(job.WithDebounce(10 * time.Second))

	return p
}

func (p *ProxyPorts) released(pp *ProxyPort) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return pp.proxyPort == 0 && !pp.configured && !pp.acknowledged
}

func (p *ProxyPorts) zeroProxyPort(pp *ProxyPort) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return pp.proxyPort == 0
}

func (p *ProxyPorts) releaseProxyPortWithWait(name string, portReuseWait time.Duration) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.releaseProxyPort(name, portReuseWait)
}

func TestPortAllocator(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := util.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	if err == nil {
		defer func() {
			os.RemoveAll(socketDir)
		}()
	}
	p := proxyPortsForTest(t)

	port, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, 0, port)

	_, _, err = p.GetProxyPort("listener1")
	require.ErrorIs(t, err, ErrProxyNotConfigured)

	// Another allocation for the same name gets the same port
	port1, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port, port1)

	// CRD proxy port is not found for redirect creation before acknowledgment
	name, pp := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Nil(t, pp)
	require.Empty(t, name)

	// Acknowledging CRD proxy port allows it to be found for redirect creation
	err = p.AckCRDProxyPort(context.Background(), "listener1")
	require.NoError(t, err)

	name, pp = p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.NotNil(t, pp)
	require.Equal(t, "listener1", name)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.Equal(t, port, pp.proxyPort)
	require.False(t, pp.Ingress)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, port, pp.rulesPort)

	// Generic allocation and acknowledgment must reject CRD ports.
	require.Error(t, p.SetProxyPort("listener1", types.ProxyTypeCRD, port, false))
	require.Error(t, p.AckProxyPort(t.Context(), "listener1"))
	require.Error(t, p.AckProxyPortWithReference(t.Context(), "listener1"))
	invalidPort, err := p.AllocatePort(pp, false)
	require.Error(t, err)
	require.Zero(t, invalidPort)
	current, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port, current)

	// CEC-owned ports are released immediately
	require.NoError(t, p.ReleaseCRDProxyPort("listener1"))
	stillAllocated, _, err := p.GetProxyPort("listener1")
	require.Error(t, err)
	require.Equal(t, uint16(0), stillAllocated)
	// A returning user does not find the released port.
	emptyName, referenced := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Nil(t, referenced)
	require.Empty(t, emptyName)

	// An endpoint that already acquired a reference must not revive a withdrawn port.
	invalidPort, err = p.AllocatePort(pp, false)
	require.Error(t, err)
	require.Zero(t, invalidPort)

	// redirect count remains until the user goes away
	require.Equal(t, 1, pp.nRedirects)
	require.Zero(t, pp.proxyPort)
	require.Nil(t, pp.releaseCancel)

	// ProxyPort can no longer be found, as it's port is zeroed
	port1b, _, err := p.GetProxyPort("listener1")
	require.ErrorIs(t, err, ErrProxyNotConfigured)
	require.Zero(t, port1b)
	require.Zero(t, pp.proxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Equal(t, 1, pp.nRedirects)
	// the port was acked, so rulesPort is still the same as the originally allocated port.
	require.Equal(t, port, pp.rulesPort)

	// Allocates the same port as the port was acked
	port2, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port, port2)

	// Allocated port is not found before acknowledgment
	name2, pp2 := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Empty(t, name2)
	require.Nil(t, pp2)

	// Acknowledging CRD proxy port allows it to be found for redirect creation
	err = p.AckCRDProxyPort(context.Background(), "listener1")
	require.NoError(t, err)

	// Acknowledged CRD proxy port is found
	name2, pp2 = p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name, name2)
	require.Equal(t, pp, pp2)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port2, pp2.proxyPort)
	require.True(t, pp2.configured)
	require.True(t, pp2.acknowledged)
	require.False(t, pp2.isStatic)
	require.Equal(t, 2, pp2.nRedirects)
	require.Equal(t, port2, pp2.rulesPort)

	// 1st release decreases the count
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, 1, pp.nRedirects)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.proxyPort)

	// 2nd release decreases the count to zero
	err = p.ReleaseProxyPort("listener1")
	require.NoError(t, err)

	require.Zero(t, pp.nRedirects)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, port2, pp.proxyPort)
	require.Equal(t, port2, pp.rulesPort)

	// extra releases return an error
	err = p.ReleaseProxyPort("listener1")
	require.Error(t, err)

	// mimic CEC reconciler releasing the port
	err = p.ReleaseCRDProxyPort("listener1")
	require.NoError(t, err)
	require.True(t, p.released(pp))

	// mimic some other process taking the port
	p.allocatedPorts[port2] = true

	// Allocate again, this time a different port is allocated
	port3, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port3)
	require.NotEqual(t, port2, port3)
	require.NotEqual(t, port, port3)
	// Ack makes the port findable and configures it to the datapath
	err = p.AckCRDProxyPort(context.Background(), "listener1")
	require.NoError(t, err)
	require.True(t, pp.acknowledged)
	require.Equal(t, port3, pp.rulesPort)

	name2, pp2 = p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, name, name2)
	require.Equal(t, pp, pp2)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port3, pp2.proxyPort)
	require.True(t, pp2.configured)
	require.True(t, pp2.acknowledged)
	require.False(t, pp2.isStatic)
	require.Equal(t, 1, pp2.nRedirects)
	require.Equal(t, port3, pp2.rulesPort)

	// Release marks the port as unallocated
	err = p.ReleaseCRDProxyPort("listener1")
	require.NoError(t, err)
	require.True(t, p.released(pp))
	require.Equal(t, 1, pp.nRedirects)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.proxyPort)
	require.Equal(t, port3, pp.rulesPort)

	inuse, exists := p.allocatedPorts[port3]
	require.True(t, exists)
	require.False(t, inuse)

	// No-one used the port so next allocation gets the same port again
	port4, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port3, port4)
	require.Equal(t, types.ProxyTypeCRD, pp.ProxyType)
	require.False(t, pp.Ingress)
	require.Equal(t, port4, pp.proxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.False(t, pp.isStatic)
	require.Equal(t, 1, pp.nRedirects)
	require.Equal(t, port3, pp.rulesPort)

	// Even an unacknowledged static allocation survives its last reference.
	require.NoError(t, p.SetProxyPort(types.DNSProxyName, types.ProxyTypeDNS, 5353, false))
	staticName, _ := p.FindByTypeWithReference(types.ProxyTypeDNS, "", false)
	err = p.ReleaseProxyPort(staticName)
	require.NoError(t, err)
	staticPort, isStatic, err := p.GetProxyPort(staticName)
	require.NoError(t, err)
	require.True(t, isStatic)
	require.Equal(t, uint16(5353), staticPort)
}

func TestRestoredPort(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := util.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	if err == nil {
		defer func() {
			os.RemoveAll(socketDir)
		}()
	}
	p := proxyPortsForTest(t)

	// simulate proxy port restored from file
	const ppName = string("cilium-http-egress")
	const restoredPort = uint16(14321)
	pp := p.proxyPorts[ppName]
	pp.proxyPort = restoredPort
	_, referenced := p.FindByTypeWithReference(types.ProxyTypeHTTP, "", false)
	require.Same(t, pp, referenced)

	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)
	require.Zero(t, pp.rulesPort)

	// Test that first allocation returns the restored port and marks it as configured
	port, err := p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.Equal(t, pp.proxyPort, port)
	require.Equal(t, restoredPort, pp.proxyPort)
	require.True(t, pp.configured, "restored proxy port not marked as configured")
	require.False(t, pp.acknowledged)

	// Simulate releasing the failed redirect after a NACK.
	err = p.ReleaseProxyPort(ppName)
	require.NoError(t, err)
	require.Zero(t, pp.proxyPort)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)

	// Allocate again, check that a new port is allocated
	port, err = p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.Equal(t, pp.proxyPort, port)
	require.NotZero(t, pp.proxyPort)
	require.NotEqual(t, restoredPort, pp.proxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)

	newPort := pp.proxyPort

	// Simulate ACK
	err = p.AckProxyPortWithReference(context.TODO(), ppName)
	require.NoError(t, err)
	require.Equal(t, newPort, pp.proxyPort)
	require.True(t, pp.configured)
	require.True(t, pp.acknowledged)
	require.Equal(t, 1, pp.nRedirects)

	// Release
	require.Nil(t, pp.releaseCancel)
	err = p.releaseProxyPortWithWait(ppName, time.Microsecond)
	require.NoError(t, err)
	require.Zero(t, pp.nRedirects)

	// wait for port reuse wait to pass
	// waiting time is set up to 1s (instead of exactly 1ms) to avoid potential flake in CI
	require.Eventually(t, func() bool {
		return p.zeroProxyPort(pp)
	}, time.Second, time.Millisecond)
	require.False(t, pp.configured)
	require.False(t, pp.acknowledged)

	// datapath port number is left as is
	require.Equal(t, newPort, pp.rulesPort)

	// Reallocation returns the previous datapath port and marks it as configured
	p.Restore(pp)
	port, err = p.AllocatePort(pp, false)
	require.NoError(t, err)
	require.Equal(t, pp.proxyPort, port)
	require.Equal(t, newPort, pp.proxyPort)
	require.True(t, pp.configured)
	require.False(t, pp.acknowledged)
}

func TestReallocateCRDProxyPort(t *testing.T) {
	testRunDir := t.TempDir()
	socketDir := util.GetSocketDir(testRunDir)
	err := os.MkdirAll(socketDir, 0o700)
	require.NoError(t, err)
	if err == nil {
		defer func() {
			os.RemoveAll(socketDir)
		}()
	}
	p := proxyPortsForTest(t)

	// First allocation using AllocateCRDProxyPort
	port1, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port1)

	// Upon a bind failure, the port would NOT be acknowledged, so it is not found
	name, pp := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Empty(t, name)
	require.Nil(t, pp)

	// Reallocation should allocate a new port
	port2, err := p.ReallocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.NotEqual(t, uint16(0), port2)
	require.NotEqual(t, port1, port2, "ReallocateCRDProxyPort should allocate a new port")

	// Acknowledge the new port
	err = p.AckCRDProxyPort(context.Background(), "listener1")
	require.NoError(t, err)

	// Verify the port was reset and new port allocated
	name2, pp2 := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Equal(t, "listener1", name2)
	require.Equal(t, port2, pp2.proxyPort)
	require.Equal(t, port2, pp2.rulesPort)
	require.True(t, pp2.configured)
	require.True(t, pp2.acknowledged)

	// Verify old port is marked as available for reuse
	inuse, exists := p.allocatedPorts[port1]
	require.True(t, exists)
	require.False(t, inuse, "old port should be marked as available for reuse")

	// Verify new port is marked as in use
	inuse2, exists2 := p.allocatedPorts[port2]
	require.True(t, exists2)
	require.True(t, inuse2, "new port should be marked as in use")

	// CRD restoration retains the previous port as a candidate, without activating it.
	require.NoError(t, p.ReleaseCRDProxyPort("listener1"))
	p.Restore(pp2)
	_, _, err = p.GetProxyPort("listener1")
	require.ErrorIs(t, err, ErrProxyNotConfigured)
	_, unavailable := p.FindByTypeWithReference(types.ProxyTypeCRD, "listener1", false)
	require.Nil(t, unavailable)
	restored, err := p.AllocateCRDProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port2, restored)
	require.NoError(t, p.AckCRDProxyPort(t.Context(), "listener1"))
	current, _, err := p.GetProxyPort("listener1")
	require.NoError(t, err)
	require.Equal(t, port2, current)
}

func TestProxyPortsPersistence(t *testing.T) {
	for _, tt := range []struct {
		name       string
		proxyType  types.ProxyType
		concurrent bool
	}{
		{name: "cilium-http-egress", proxyType: types.ProxyTypeHTTP},
		{name: "cilium-dns-egress", proxyType: types.ProxyTypeDNS},
		{name: "ns/cec/listener", proxyType: types.ProxyTypeCRD},
		{name: "ns/cec/concurrent", proxyType: types.ProxyTypeCRD, concurrent: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := proxyPortsForTest(t)
			p.proxyPortsPath = filepath.Join(t.TempDir(), proxyPortsFile)
			var port uint16
			var err error
			switch tt.proxyType {
			case types.ProxyTypeDNS:
				// DNS binds its own socket and registers the bound port.
				port = 5353
				require.NoError(t, p.SetProxyPort(tt.name, tt.proxyType, port, false))
				require.NoError(t, p.AckProxyPortWithReference(t.Context(), tt.name))
			case types.ProxyTypeCRD:
				// CRD ports have a separate allocation sequence.
				port, err = p.AllocateCRDProxyPort(tt.name)
				require.NoError(t, err)
				require.NoError(t, p.AckCRDProxyPort(t.Context(), tt.name))
			default:
				// Other types drive port allocation from redirect creation.
				name, pp := p.FindByTypeWithReference(tt.proxyType, "", false)
				require.Equal(t, tt.name, name)
				require.NotNil(t, pp)
				port, err = p.AllocatePort(pp, false)
				require.NoError(t, err)
				require.NoError(t, p.AckProxyPort(t.Context(), name))
			}
			if tt.concurrent {
				var wg sync.WaitGroup
				wg.Go(func() {
					for range 100 {
						_, err := p.ReallocateCRDProxyPort(tt.name)
						require.NoError(t, err)
						require.NoError(t, p.AckCRDProxyPort(t.Context(), tt.name))
					}
				})
				for range 100 {
					require.NoError(t, p.StoreProxyPorts(t.Context()))
					current, _, err := p.GetProxyPort(tt.name)
					if err == nil {
						require.NotZero(t, current)
					} else {
						require.ErrorIs(t, err, ErrProxyNotConfigured)
					}
				}
				wg.Wait()
				port, _, err = p.GetProxyPort(tt.name)
				require.NoError(t, err)
			}
			require.NoError(t, p.StoreProxyPorts(t.Context()))
			data, err := os.ReadFile(p.proxyPortsPath)
			require.NoError(t, err)
			require.JSONEq(t, fmt.Sprintf("{%q:{\"type\":%q,\"ingress\":false,\"port\":%d}}", tt.name, tt.proxyType, port), string(data))

			restored := proxyPortsForTest(t)
			restored.proxyPortsPath = p.proxyPortsPath
			restored.restoredProxyPortsStaleLimit = 15
			health, _ := cell.NewSimpleHealth()
			require.NoError(t, restored.RestoreProxyPorts(t.Context(), health))
			if tt.proxyType == types.ProxyTypeCRD {
				_, pp := restored.FindByTypeWithReference(tt.proxyType, tt.name, false)
				require.Nil(t, pp, "restored CRD ports require a new CEC ACK")
				actual, err := restored.AllocateCRDProxyPort(tt.name)
				require.NoError(t, err)
				require.Equal(t, port, actual)
				require.NoError(t, restored.AckCRDProxyPort(t.Context(), tt.name))
			} else if tt.proxyType == types.ProxyTypeDNS {
				actual, isStatic, err := restored.GetProxyPort(tt.name)
				require.NoError(t, err)
				require.False(t, isStatic)
				require.Equal(t, port, actual)
				require.NoError(t, restored.SetProxyPort(tt.name, tt.proxyType, actual, false))
				require.NoError(t, restored.AckProxyPortWithReference(t.Context(), tt.name))
			}
			actual, isStatic, err := restored.GetProxyPort(tt.name)
			require.NoError(t, err)
			require.Equal(t, tt.proxyType == types.ProxyTypeDNS, isStatic)
			require.Equal(t, port, actual, "restoration must preserve the persisted port")
		})
	}
}
