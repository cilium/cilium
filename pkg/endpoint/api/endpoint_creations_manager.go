// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

type endpointCreationRequest struct {
	// cancel is the cancellation function that can be called to cancel
	// this endpoint create request
	cancel context.CancelFunc

	// endpoint is the endpoint being added in the request
	endpoint *endpoint.Endpoint

	// started is the timestamp on when the processing has started
	started time.Time
}

type EndpointCreationManager interface {
	NewCreateRequest(ep *endpoint.Endpoint, cancel context.CancelFunc)
	EndCreateRequest(ep *endpoint.Endpoint) bool
	CancelCreateRequest(ep *endpoint.Endpoint)
}

type endpointCreationManager struct {
	mutex     lock.Mutex
	clientset client.Clientset
	requests  map[string]*endpointCreationRequest
}

var _ EndpointCreationManager = &endpointCreationManager{}

func newEndpointCreationManager(cs client.Clientset) EndpointCreationManager {
	mgr := &endpointCreationManager{
		requests:  map[string]*endpointCreationRequest{},
		clientset: cs,
	}

	debug.RegisterStatusObject("ongoing-endpoint-creations", mgr)

	return mgr
}

func (m *endpointCreationManager) NewCreateRequest(ep *endpoint.Endpoint, cancel context.CancelFunc) {
	// Tracking is only performed if Kubernetes pod names are available.
	// The endpoint create logic already ensures that IPs and CNI attachment ID
	// are unique and thus tracking is not required outside of the
	// Kubernetes context
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return
	}

	cepName := ep.GetK8sNamespaceAndCEPName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[cepName]; ok {
		ep.Logger(endpointAPIModuleID).Warn("Cancelling obsolete endpoint creating due to new create for same cep name")
		req.cancel()
	}

	ep.Logger(endpointAPIModuleID).Debug("New create request")
	m.requests[cepName] = &endpointCreationRequest{
		cancel:   cancel,
		endpoint: ep,
		started:  time.Now(),
	}
}

func (m *endpointCreationManager) EndCreateRequest(ep *endpoint.Endpoint) bool {
	if !ep.K8sNamespaceAndPodNameIsSet() || !m.clientset.IsEnabled() {
		return false
	}

	cepName := ep.GetK8sNamespaceAndCEPName()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if req, ok := m.requests[cepName]; ok {
		if req.endpoint == ep {
			ep.Logger(endpointAPIModuleID).Debug("End of create request")
			delete(m.requests, cepName)
			return true
		}
	}

	return false
}

func (m *endpointCreationManager) CancelCreateRequest(ep *endpoint.Endpoint) {
	if m.EndCreateRequest(ep) {
		ep.Logger(endpointAPIModuleID).Warn("Cancelled endpoint create request due to receiving endpoint delete request")
	}
}

func (m *endpointCreationManager) DebugStatus() (output string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, req := range m.requests {
		output += fmt.Sprintf("- %s: %s\n", req.started.String(), req.endpoint.String())
	}
	return
}
