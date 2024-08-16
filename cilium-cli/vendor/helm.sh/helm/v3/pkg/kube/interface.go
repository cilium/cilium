/*
Copyright The Helm Authors.

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

package kube

import (
	"io"
	"time"

	v1 "k8s.io/api/core/v1"
)

// Interface represents a client capable of communicating with the Kubernetes API.
//
// A KubernetesClient must be concurrency safe.
type Interface interface {
	// Create creates one or more resources.
	Create(resources ResourceList) (*Result, error)

	// Wait waits up to the given timeout for the specified resources to be ready.
	Wait(resources ResourceList, timeout time.Duration) error

	// WaitWithJobs wait up to the given timeout for the specified resources to be ready, including jobs.
	WaitWithJobs(resources ResourceList, timeout time.Duration) error

	// Delete destroys one or more resources.
	Delete(resources ResourceList) (*Result, []error)

	// WatchUntilReady watches the resources given and waits until it is ready.
	//
	// This method is mainly for hook implementations. It watches for a resource to
	// hit a particular milestone. The milestone depends on the Kind.
	//
	// For Jobs, "ready" means the Job ran to completion (exited without error).
	// For Pods, "ready" means the Pod phase is marked "succeeded".
	// For all other kinds, it means the kind was created or modified without
	// error.
	WatchUntilReady(resources ResourceList, timeout time.Duration) error

	// Update updates one or more resources or creates the resource
	// if it doesn't exist.
	Update(original, target ResourceList, force bool) (*Result, error)

	// Build creates a resource list from a Reader.
	//
	// Reader must contain a YAML stream (one or more YAML documents separated
	// by "\n---\n")
	//
	// Validates against OpenAPI schema if validate is true.
	Build(reader io.Reader, validate bool) (ResourceList, error)

	// WaitAndGetCompletedPodPhase waits up to a timeout until a pod enters a completed phase
	// and returns said phase (PodSucceeded or PodFailed qualify).
	WaitAndGetCompletedPodPhase(name string, timeout time.Duration) (v1.PodPhase, error)

	// IsReachable checks whether the client is able to connect to the cluster.
	IsReachable() error
}

// InterfaceExt is introduced to avoid breaking backwards compatibility for Interface implementers.
//
// TODO Helm 4: Remove InterfaceExt and integrate its method(s) into the Interface.
type InterfaceExt interface {
	// WaitForDelete wait up to the given timeout for the specified resources to be deleted.
	WaitForDelete(resources ResourceList, timeout time.Duration) error
}

var _ Interface = (*Client)(nil)
var _ InterfaceExt = (*Client)(nil)
