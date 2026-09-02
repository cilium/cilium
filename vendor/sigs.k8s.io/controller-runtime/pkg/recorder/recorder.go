/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package recorder defines interfaces for working with Kubernetes event recorders.
//
// You can use these to emit Kubernetes events associated with a particular Kubernetes
// object.
package recorder

import (
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/tools/record"
)

// EventRecorder combines both events.EventRecorder and events.AnnotatedEventRecorder
// so that callers only need a single recorder to emit both regular and annotated events.
type EventRecorder interface {
	events.EventRecorder
	events.AnnotatedEventRecorder
}

// Provider knows how to generate new event recorders with given name.
type Provider interface {
	// GetEventRecorderFor returns an EventRecorder for the old events API.
	//
	// Deprecated: this uses the old events API and will be removed in a future release. Please use GetEventRecorder instead.
	GetEventRecorderFor(name string) record.EventRecorder
	// GetEventRecorder returns an EventRecorder with given name.
	//
	// The name is used as the reportingController of events.k8s.io/v1 Events
	// and must be a valid Kubernetes qualified name. client-go derives the
	// reportingInstance by appending "-" and the current hostname to
	// reportingController. reportingInstance must be no more than 128
	// characters, so callers should ensure that len(name) + 1 + len(hostname)
	// is at most 128.
	// The returned recorder supports both Eventf and AnnotatedEventf.
	GetEventRecorder(name string) EventRecorder
}
