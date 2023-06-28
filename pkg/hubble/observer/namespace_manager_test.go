// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func TestNamespaceManager(t *testing.T) {
	// mock time
	currentTime := time.Time{}
	mgr := NewNamespaceManager()
	// use the mocked time
	mgr.nowFunc = func() time.Time {
		return currentTime
	}
	advanceTime := func(d time.Duration) {
		// update our currentTime
		currentTime = currentTime.Add(d)
		// trigger cleanupNamespaces after we advance time to ensure it's run
		mgr.cleanupNamespaces()
	}

	// we start with no namespaces
	expected := []*observerpb.Namespace{}
	assert.Equal(t, expected, mgr.GetNamespaces())

	// add a few namespaces

	// out of order, we'll verify it's sorted when we call GetNamespaces later
	mgr.AddNamespace(&observerpb.Namespace{Namespace: "ns-2"})
	mgr.AddNamespace(&observerpb.Namespace{Namespace: "ns-1"})

	// namespaces that we added should be returned, sorted
	expected = []*observerpb.Namespace{
		{Namespace: "ns-1"},
		{Namespace: "ns-2"},
	}
	assert.Equal(t, expected, mgr.GetNamespaces())

	// advance the clock by 1/2 the namespaceTTL and verify our namespaces are still known
	advanceTime(namespaceTTL / 2)
	assert.Equal(t, expected, mgr.GetNamespaces())

	// add more namespaces now that the clock has been advanced
	mgr.AddNamespace(&observerpb.Namespace{Namespace: "ns-1"})
	mgr.AddNamespace(&observerpb.Namespace{Namespace: "ns-3"})
	mgr.AddNamespace(&observerpb.Namespace{Namespace: "ns-4"})

	// we expect all namespaces to exist, the first 2 are 30 minutes old, and the
	// next two are 0 minutes old
	expected = []*observerpb.Namespace{
		{Namespace: "ns-1"},
		{Namespace: "ns-2"},
		{Namespace: "ns-3"},
		{Namespace: "ns-4"},
	}
	assert.Equal(t, expected, mgr.GetNamespaces())

	// advance the clock another 1/2 TTL and add a minute to push us past the TTL
	advanceTime((namespaceTTL / 2) + time.Minute)

	// we expect ns2 to be gone because it's an hour old, and ns-1 got refreshed
	// when we added ns-3 and ns-4 30 minutes ago
	expected = []*observerpb.Namespace{
		{Namespace: "ns-1"},
		{Namespace: "ns-3"},
		{Namespace: "ns-4"},
	}
	assert.Equal(t, expected, mgr.GetNamespaces())

	// advance the clock another 1/2 TTL and add a minute to push us past the TTL again
	advanceTime((namespaceTTL / 2) + time.Minute)

	// no namespaces left, nothing has been refreshed
	assert.Equal(t, []*observerpb.Namespace{}, mgr.GetNamespaces())
}
