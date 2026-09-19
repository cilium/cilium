// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServersInitialization(t *testing.T) {
	tests := []struct {
		name                   string
		address                []string
		expectedServerCount    int
		exptectedServerAddress []string
	}{
		{
			name:                   "Initialize http server listening on all ports",
			address:                []string{""},
			expectedServerCount:    1,
			exptectedServerAddress: []string{":4240"},
		},
		{
			name:                   "Initialize http server listening on ipv4 address",
			address:                []string{"192.168.1.4"},
			expectedServerCount:    1,
			exptectedServerAddress: []string{"192.168.1.4:4240"},
		},
		{
			name:                   "Initialize http server listening on ipv4 and ipv6 address",
			address:                []string{"192.168.1.4", "fc00:c111::2"},
			expectedServerCount:    2,
			exptectedServerAddress: []string{"192.168.1.4:4240", "[fc00:c111::2]:4240"},
		},
		{
			name:                   "No address means no listener",
			address:                []string{},
			expectedServerCount:    0,
			exptectedServerAddress: nil,
		},
	}

	for _, tt := range tests {
		s := NewServers(tt.address, 4240)
		assert.NotNil(t, s)
		assert.Len(t, s.httpServers, tt.expectedServerCount, "Number of listen address doesn't match")
		for i := range s.httpServers {
			assert.Equal(t, tt.exptectedServerAddress[i], s.listenAddr(i))
		}
	}
}

func TestMain(m *testing.M) {
	listenRetryInterval = 10 * time.Millisecond
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func serving(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// An address that is not assignable must not stop the listeners that did bind.
func TestServeRetriesWithoutStoppingOthers(t *testing.T) {
	port := freePort(t)

	// 192.0.2.0/24 is TEST-NET-1: never assigned to an interface.
	s := NewServers([]string{"127.0.0.1", "192.0.2.1"}, port)
	go s.Serve()
	defer s.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%d/hello", port)
	require.Eventually(t, func() bool { return serving(url) },
		5*time.Second, 20*time.Millisecond, "assignable address must serve while another fails")

	time.Sleep(50 * time.Millisecond)
	require.True(t, serving(url), "must keep serving while the other address retries")
}

// A listener must follow the address when it changes.
func TestServeFollowsAddressChange(t *testing.T) {
	port := freePort(t)

	var mu sync.Mutex
	host := "192.0.2.1"
	s := NewServersFunc(func() []string {
		mu.Lock()
		defer mu.Unlock()
		return []string{host}
	}, port)
	go s.Serve()
	defer s.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%d/hello", port)
	require.False(t, serving(url), "must not serve before the address is assignable")

	mu.Lock()
	host = "127.0.0.1"
	mu.Unlock()

	require.Eventually(t, func() bool { return serving(url) },
		5*time.Second, 20*time.Millisecond, "listener must bind the new address")
}

// A family gaining an address must not move another family's listener.
func TestServeAddressPositionStable(t *testing.T) {
	port := freePort(t)
	var mu sync.Mutex
	// v4 enabled but absent, v6 present: one empty slot, one address.
	ips := []string{"", "::1"}
	s := NewServersFunc(func() []string {
		mu.Lock()
		defer mu.Unlock()
		return ips
	}, port)
	go s.Serve()
	defer s.Shutdown()

	url6 := fmt.Sprintf("http://[::1]:%d/hello", port)
	require.Eventually(t, func() bool { return serving(url6) }, 5*time.Second, 20*time.Millisecond,
		"v6 must serve")

	mu.Lock()
	ips = []string{"127.0.0.1", "::1"}
	mu.Unlock()

	require.Eventually(t, func() bool {
		return serving(url6) && serving(fmt.Sprintf("http://127.0.0.1:%d/hello", port))
	}, 5*time.Second, 20*time.Millisecond, "both families must serve once v4 appears")
}

// Shutdown must stop Serve while a listener is waiting for an address.
func TestShutdownWhileWaitingForAddress(t *testing.T) {
	// Two listeners created, but the address list shrinks to one: listener 1
	// has no address and only ever waits.
	n := 2
	s := NewServersFunc(func() []string {
		if n == 2 {
			n = 1
			return []string{"127.0.0.1", "::1"}
		}
		return []string{"127.0.0.1"}
	}, freePort(t))

	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	time.Sleep(100 * time.Millisecond)
	s.Shutdown()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Shutdown: a listener with no address spins forever")
	}
}
