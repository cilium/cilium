// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package signaler

import "testing"

// Make sure that the receiver only observes a single event even if multiple
// events are sent.
func TestEventCorrelation(t *testing.T) {
	s := NewBGPCPSignaler()

	// Send two events
	s.Event(nil)
	s.Event(nil)

	// One event should be received
	select {
	case <-s.Sig:
	default:
		t.Fatal("expected event to be received")
	}

	// The second event should be correlated and shouldn't received
	select {
	case <-s.Sig:
		t.Fatal("expected event to be correlated")
	default:
	}
}
