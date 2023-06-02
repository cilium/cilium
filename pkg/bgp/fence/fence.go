// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fence

import (
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/types"
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

// metaGetter specifies the methods needed by (*Meta).FromObjectMeta.
// This is used extract metadata from a corev1 or a slim_corev1 object.
type metaGetter interface {
	GetResourceVersion() string
	GetUID() types.UID
}

// FromObjectMeta allocates a meta derived from
// a k8s ObjectMeta and stores it at the memory
// pointed to by m.
func (m *Meta) FromObjectMeta(mg metaGetter) error {
	rev, err := strconv.ParseUint(mg.GetResourceVersion(), 10, 64)
	if err != nil {
		return fmt.Errorf("ObjectMeta.ResourceVersion must be parsible to Uint64")
	}
	(*m).Rev = rev
	(*m).UUID = string(mg.GetUID())
	return nil
}
