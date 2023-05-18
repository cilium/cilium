// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/cilium/checkmate"
)

type ServiceHealthServerSuite struct{}

var _ = Suite(&ServiceHealthServerSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *ServiceHealthServerSuite) TestServiceHealthServer_UpsertService(c *C) {
	f := NewMockHealthHTTPServerFactory()
	h := WithHealthHTTPServerFactory(f)

	// Insert svc1
	h.UpsertService(1, "default", "svc1", 1, 32000)
	c.Assert(f.ServiceByPort(32000).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32000).Service.Name, Equals, "svc1")
	c.Assert(f.ServiceByPort(32000).LocalEndpoints, Equals, 1)

	// Disable svc1 port
	h.UpsertService(1, "default", "svc1", 1, 0)
	c.Assert(f.ServiceByPort(32000), IsNil)

	// Re-enable svc1 port
	h.UpsertService(1, "default", "svc1", 1, 32000)
	c.Assert(f.ServiceByPort(32000).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32000).Service.Name, Equals, "svc1")
	c.Assert(f.ServiceByPort(32000).LocalEndpoints, Equals, 1)

	// Change svc1 port
	h.UpsertService(1, "default", "svc1", 2, 32001)
	c.Assert(f.ServiceByPort(32000), IsNil)
	c.Assert(f.ServiceByPort(32001).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(f.ServiceByPort(32001).LocalEndpoints, Equals, 2)

	// Update svc1 count
	h.UpsertService(1, "default", "svc1", 3, 32001)
	c.Assert(f.ServiceByPort(32001).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(f.ServiceByPort(32001).LocalEndpoints, Equals, 3)

	// Add svc1 clone (uses same port, must be ref-counted)
	h.UpsertService(100, "default", "svc1", 3, 32001)
	c.Assert(f.ServiceByPort(32001).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(f.ServiceByPort(32001).LocalEndpoints, Equals, 3)

	// Insert svc2
	h.UpsertService(2, "default", "svc2", 0, 32002)
	c.Assert(f.ServiceByPort(32002).Service.Namespace, Equals, "default")
	c.Assert(f.ServiceByPort(32002).Service.Name, Equals, "svc2")
	c.Assert(f.ServiceByPort(32002).LocalEndpoints, Equals, 0)

	// Delete svc1 clone
	h.DeleteService(100)
	c.Assert(f.ServiceByPort(32001), Not(IsNil))
	c.Assert(f.ServiceByPort(32002), Not(IsNil))

	// Delete svc1
	h.DeleteService(1)
	c.Assert(f.ServiceByPort(32001), IsNil)
	c.Assert(f.ServiceByPort(32002), Not(IsNil))

	// Delete svc2
	h.DeleteService(2)
	c.Assert(f.ServiceByPort(32001), IsNil)
	c.Assert(f.ServiceByPort(32002), IsNil)
}

func (s *ServiceHealthServerSuite) Test_httpHealthServer_ServeHTTP(c *C) {
	h := &httpHealthServer{}
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Set local endpoints, server must respond with HTTP 200
	h.updateService(NewService("default", "svc", 1))
	resp, err := http.Get(ts.URL)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
	resp.Body.Close()

	// Remove local endpoints, server must respond with HTTP 503
	h.updateService(NewService("default", "svc", 0))
	resp, err = http.Get(ts.URL)
	c.Assert(err, IsNil)
	c.Assert(resp.StatusCode, Equals, http.StatusServiceUnavailable)
	resp.Body.Close()
}
