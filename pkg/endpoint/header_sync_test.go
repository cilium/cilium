// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/policy"
)

// TestSyncEndpointHeaderFileBeforeTriggerInit checks that a header file sync
// requested before the DNS history trigger exists is replayed once the trigger
// is initialized, instead of being dropped.
func TestSyncEndpointHeaderFileBeforeTriggerInit(t *testing.T) {
	synced := make(chan struct{}, 1)
	ep := newRegenTestEndpoint(t, &policy.Repository{}, &policy.EndpointPolicy{})
	ep.dnsRulesAPI = noopDNSRulesAPI{onRead: func() {
		select {
		case synced <- struct{}{}:
		default:
		}
	}}
	t.Cleanup(func() {
		if tr := ep.dnsHistoryTrigger.Swap(nil); tr != nil {
			tr.Shutdown()
		}
	})

	// No trigger yet: the request must be remembered, not lost.
	require.Nil(t, ep.dnsHistoryTrigger.Load())
	ep.SyncEndpointHeaderFile()

	select {
	case <-synced:
		t.Fatal("header file sync ran before the trigger was initialized")
	default:
	}

	ep.initDNSHistoryTrigger()

	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		t.Fatal("header file sync requested before trigger init was lost")
	}
}
