// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestServiceHealthServer_UpsertService(t *testing.T) {
	logger := hivetest.Logger(t)
	f := NewMockHealthHTTPServerFactory(logger)
	h := WithHealthHTTPServerFactory(logger, f)

	// Insert svc1
	h.UpsertService(1, "default", "svc1", 1, 32000)
	require.Equal(t, "default", f.ServiceByPort(32000).Service.Namespace)
	require.Equal(t, "svc1", f.ServiceByPort(32000).Service.Name)
	require.Equal(t, 1, f.ServiceByPort(32000).LocalEndpoints)

	// Disable svc1 port
	h.UpsertService(1, "default", "svc1", 1, 0)
	require.Nil(t, f.ServiceByPort(32000))

	// Re-enable svc1 port
	h.UpsertService(1, "default", "svc1", 1, 32000)
	require.Equal(t, "default", f.ServiceByPort(32000).Service.Namespace)
	require.Equal(t, "svc1", f.ServiceByPort(32000).Service.Name)
	require.Equal(t, 1, f.ServiceByPort(32000).LocalEndpoints)

	// Change svc1 port
	h.UpsertService(1, "default", "svc1", 2, 32001)
	require.Nil(t, f.ServiceByPort(32000))
	require.Equal(t, "default", f.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, "svc1", f.ServiceByPort(32001).Service.Name)
	require.Equal(t, 2, f.ServiceByPort(32001).LocalEndpoints)

	// Update svc1 count
	h.UpsertService(1, "default", "svc1", 3, 32001)
	require.Equal(t, "default", f.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, "svc1", f.ServiceByPort(32001).Service.Name)
	require.Equal(t, 3, f.ServiceByPort(32001).LocalEndpoints)

	// Add svc1 clone (uses same port, must be ref-counted)
	h.UpsertService(100, "default", "svc1", 3, 32001)
	require.Equal(t, "default", f.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, "svc1", f.ServiceByPort(32001).Service.Name)
	require.Equal(t, 3, f.ServiceByPort(32001).LocalEndpoints)

	// Insert svc2
	h.UpsertService(2, "default", "svc2", 0, 32002)
	require.Equal(t, "default", f.ServiceByPort(32002).Service.Namespace)
	require.Equal(t, "svc2", f.ServiceByPort(32002).Service.Name)
	require.Equal(t, 0, f.ServiceByPort(32002).LocalEndpoints)

	// Delete svc1 clone
	h.DeleteService(100)
	require.NotNil(t, f.ServiceByPort(32001))
	require.NotNil(t, f.ServiceByPort(32002))

	// Delete svc1
	h.DeleteService(1)
	require.Nil(t, f.ServiceByPort(32001))
	require.NotNil(t, f.ServiceByPort(32002))

	// Delete svc2
	h.DeleteService(2)
	require.Nil(t, f.ServiceByPort(32001))
	require.Nil(t, f.ServiceByPort(32002))
}

func Test_httpHealthServer_ServeHTTP(t *testing.T) {
	h := &httpHealthServer{}
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Set local endpoints, server must respond with HTTP 200
	h.updateService(NewService("default", "svc", 2))
	resp, err := http.Get(ts.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assertRespHeader(t, resp, "Content-Type", "application/json")
	assertRespHeader(t, resp, "X-Content-Type-Options", "nosniff")
	assertRespHeader(t, resp, "X-Load-Balancing-Endpoint-Weight", "2")
	resp.Body.Close()

	// Remove local endpoints, server must respond with HTTP 503
	h.updateService(NewService("default", "svc", 0))
	resp, err = http.Get(ts.URL)
	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	resp.Body.Close()
}

func assertRespHeader(t *testing.T, resp *http.Response, key, val string) {
	if !cmp.Equal(resp.Header[key], []string{val}) {
		t.Errorf("Want response header: %q: %q, got: %q, %q,", key, []string{val}, key, resp.Header[key])
	}
}
