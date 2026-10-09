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

// fakeDNSProxyReadiness is a controllable DNSProxyReadiness for tests: the
// channel it returns stays open until the test closes it.
type fakeDNSProxyReadiness struct {
	ch chan struct{}
}

func (f fakeDNSProxyReadiness) DNSProxyReady() <-chan struct{} { return f.ch }

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

func TestPolicyHasDNSRedirect(t *testing.T) {
	tests := []struct {
		name string
		sp   policy.SelectorPolicy
		want bool
	}{
		{"nil policy", nil, false},
		{"no redirect filters", &testSelectorPolicy{}, false},
		{"http only", &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{httpTuple()}}, false},
		{"dns", &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{dnsTuple()}}, true},
		{"http and dns", &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{httpTuple(), dnsTuple()}}, true},
		{"nil tuple policy", &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{{Policy: nil}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, policyHasDNSRedirect(tt.sp))
		})
	}
}

// The gate must not block when the policy has no DNS redirect, nor when no
// readiness signal is wired, even if the readiness channel never closes.
func TestWaitForDNSProxyReadyNotGated(t *testing.T) {
	neverReady := make(chan struct{})

	t.Run("no DNS redirect", func(t *testing.T) {
		e := &Endpoint{dnsProxyReady: fakeDNSProxyReadiness{ch: neverReady}, aliveCtx: context.Background()}
		sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{httpTuple()}}
		select {
		case err := <-runGate(e, sp):
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("gate blocked for a policy with no DNS redirect")
		}
	})

	t.Run("nil readiness", func(t *testing.T) {
		e := &Endpoint{aliveCtx: context.Background()}
		sp := &testSelectorPolicy{redirectFilters: []policy.PerSelectorPolicyTuple{dnsTuple()}}
		select {
		case err := <-runGate(e, sp):
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("gate blocked when no readiness signal is wired")
		}
	})
}

// With a DNS redirect, the gate blocks until the DNS proxy signals ready, then
// returns nil.
func TestWaitForDNSProxyReadyWaitsForReady(t *testing.T) {
	ready := make(chan struct{})
	e := &Endpoint{dnsProxyReady: fakeDNSProxyReadiness{ch: ready}, aliveCtx: context.Background()}
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
	e := &Endpoint{dnsProxyReady: fakeDNSProxyReadiness{ch: neverReady}, aliveCtx: ctx}
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
