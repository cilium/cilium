// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

type EventKind string

const (
	Sync   EventKind = "sync"
	Upsert EventKind = "upsert"
	Delete EventKind = "delete"
)

// Event emitted from resource.
type Event[T k8sRuntime.Object] struct {
	Kind   EventKind
	Key    Key
	Object T

	// Done marks the event as processed.  If err is non-nil, the
	// key of the object is requeued and the processing retried at
	// a later time with a potentially new version of the object.
	//
	// No new events for this key will be emitted until Done() is
	// invoked.
	Done func(err error)
}
