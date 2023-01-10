// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fence

import (
	"fmt"
	"strconv"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// Fencer provides a method set to prevent processing out of order events.
//
// Fencer will keep track of the last seen revision (monotonically increasing event id)
// for each seen UUID (globally unique identifier for a resource producing an event.)
type Fencer map[string]uint64

// Fence evalutes the passed in meta and informs the caller
// whether to not process the event (fence) or not process
// the event (no fence)
//
// True is returned when the caller should fence the event.
// False is returned when the caller should not.
func (f Fencer) Fence(m Meta) bool {
	var (
		revSeen uint64
		ok      bool
	)
	if revSeen, ok = f[m.UUID]; !ok {
		// first time we are seeing this
		// resource; add it, don't fence.
		f[m.UUID] = m.Rev
		return false
	}

	if m.Rev < revSeen {
		// stale event, fence off.
		return true
	}

	// new event, store rev and don't fence.
	f[m.UUID] = m.Rev
	return false
}

// Clear removes the uuid and revision from its
// internal storage.
//
// This method should only be invoked once the caller
// can ensure the provided UUID will not be seen again.
func (f Fencer) Clear(uuid string) {
	delete(f, uuid)
}

// Meta provides metadata from the resource which
// triggered this package's events.
type Meta struct {
	// UUID is an immutable identifier for resource producing
	// this event.
	UUID string
	// Rev is a revision number in a total order of revision numbers
	// for the resource producing this event.
	Rev uint64
}

// FromSlimObjectMeta allocates a meta derived from
// a slim k8s ObjectMeta and stores it at the memory
// pointed to by m.
func (m *Meta) FromSlimObjectMeta(om *slim_metav1.ObjectMeta) error {
	rev, err := strconv.ParseUint(om.ResourceVersion, 10, 64)
	if err != nil {
		return fmt.Errorf("ObjectMeta.ResourceVersion must be parsible to Uint64")
	}
	(*m).Rev = rev
	(*m).UUID = string(om.UID)
	return nil
}

// FromSlimObjectMeta allocates a meta derived from
// a k8s ObjectMeta and stores it at the memory
// pointed to by m.
func (m *Meta) FromObjectMeta(om *v1.ObjectMeta) error {
	rev, err := strconv.ParseUint(om.ResourceVersion, 10, 64)
	if err != nil {
		return fmt.Errorf("ObjectMeta.ResourceVersion must be parsible to Uint64")
	}
	(*m).Rev = rev
	(*m).UUID = string(om.UID)
	return nil
}
