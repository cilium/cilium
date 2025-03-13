// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"log/slog"
)

// MockHealthHTTPServerFactory mocks the healthHTTPServerFactory interface
type MockHealthHTTPServerFactory struct {
	logger        *slog.Logger
	serversByPort map[uint16]*mockHealthServer
}

// NewMockHealthHTTPServerFactory creates a new health server factory for testing
func NewMockHealthHTTPServerFactory(logger *slog.Logger) *MockHealthHTTPServerFactory {
	return &MockHealthHTTPServerFactory{
		logger:        logger,
		serversByPort: map[uint16]*mockHealthServer{},
	}
}

// ServiceByPort returns the service for a given health check node port
func (m *MockHealthHTTPServerFactory) ServiceByPort(port uint16) *Service {
	if srv, ok := m.serversByPort[port]; ok {
		return srv.svc
	}
	return nil
}

func (m *MockHealthHTTPServerFactory) newHTTPHealthServer(port uint16, svc *Service) healthHTTPServer {
	m.serversByPort[port] = &mockHealthServer{
		port:    port,
		svc:     svc,
		factory: m,
	}

	return m.serversByPort[port]
}

type mockHealthServer struct {
	port    uint16
	svc     *Service
	factory *MockHealthHTTPServerFactory
}

func (m *mockHealthServer) updateService(svc *Service) {
	m.svc = svc
}

func (m *mockHealthServer) shutdown() {
	delete(m.factory.serversByPort, m.port)
}
