// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/policy"
)

// gateTestProxy is a controllable EndpointProxy for tests: DNSProxyReady
// returns a channel that stays open until the test closes it. All other proxy
// methods come from the embedded FakeEndpointProxy.
type gateTestProxy struct {
	*FakeEndpointProxy
	ch chan struct{}
}

func (p *gateTestProxy) DNSProxyReady() <-chan struct{} { return p.ch }

func newGateTestProxy(ch chan struct{}) *gateTestProxy {
	return &gateTestProxy{FakeEndpointProxy: &FakeEndpointProxy{}, ch: ch}
}

func dnsTuple() policy.PerSelectorPolicyTuple {
	return policy.PerSelectorPolicyTuple{Policy: &policy.PerSelectorPolicy{L7Parser: policy.ParserTypeDNS}}
}

func httpTuple() policy.PerSelectorPolicyTuple {
	return policy.PerSelectorPolicyTuple{Policy: &policy.PerSelectorPolicy{L7Parser: policy.ParserTypeHTTP}}
}

// runGate calls waitForDNSProxyReady in a goroutine so tests can assert on
// whether and when it returns.
func runGate(e *Endpoint, sp policy.SelectorPolicy) <-chan error {
	done := make(chan error, 1)
	go func() { done <- e.waitForDNSProxyReady(sp) }()
	return done
}

// The gate must not block when the policy has no DNS redirect, nor when no
// proxy is configured, even if the readiness channel never closes.
func TestWaitForDNSProxyReadyNotGated(t *testing.T) {
	neverReady := make(chan struct{})

	t.Run("no DNS redirect", func(t *testing.T) {
		e := &Endpoint{proxy: newGateTestProxy(neverReady), aliveCtx: context.Background()}
		sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{httpTuple()}}
		select {
		case err := <-runGate(e, sp):
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("gate blocked for a policy with no DNS redirect")
		}
	})

	t.Run("proxy disabled", func(t *testing.T) {
		e := &Endpoint{aliveCtx: context.Background()}
		sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{dnsTuple()}}
		select {
		case err := <-runGate(e, sp):
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("gate blocked when no proxy is configured")
		}
	})
}

// With a DNS redirect, the gate blocks until the DNS proxy signals ready, then
// returns nil.
func TestWaitForDNSProxyReadyWaitsForReady(t *testing.T) {
	ready := make(chan struct{})
	e := &Endpoint{proxy: newGateTestProxy(ready), aliveCtx: context.Background()}
	sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{dnsTuple()}}

	done := runGate(e, sp)

	select {
	case <-done:
		t.Fatal("gate returned before DNS proxy signaled ready")
	case <-time.After(50 * time.Millisecond):
	}

	close(ready)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("gate did not return after DNS proxy signaled ready")
	}
}

// If the endpoint is torn down while waiting, the gate returns the aliveCtx
// error rather than blocking forever.
func TestWaitForDNSProxyReadyCtxCancel(t *testing.T) {
	neverReady := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	e := &Endpoint{proxy: newGateTestProxy(neverReady), aliveCtx: ctx}
	sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{dnsTuple()}}

	done := runGate(e, sp)

	select {
	case <-done:
		t.Fatal("gate returned before aliveCtx was canceled")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("gate did not return after aliveCtx was canceled")
	}
}
