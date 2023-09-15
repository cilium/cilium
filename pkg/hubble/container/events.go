// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package container

import (
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

type EventWriter interface {
	Write(*v1.Event) error
}

type EventReader interface {
	Iterator() EventIterator
}

type EventReadWriter interface {
	EventWriter
	EventReader
}

type EventIterator interface {
	Next() (*v1.Event, error)
	Close() error
}
