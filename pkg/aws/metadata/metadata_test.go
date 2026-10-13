// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/lock"
)

func TestGetInterfaceAddresses(t *testing.T) {
	const macPath = "/latest/meta-data/network/interfaces/macs/06:ff:f7:8b:c3:95/"
	var mu lock.Mutex
	paths := map[string]string{}
	set := func(path, body string) {
		mu.Lock()
		defer mu.Unlock()
		paths[macPath+path] = body
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			w.Write([]byte("token"))
			return
		}
		mu.Lock()
		body, ok := paths[r.URL.Path]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	m := &metadataClient{client: imds.New(imds.Options{Endpoint: srv.URL})}

	set("local-ipv4s", "192.168.78.248\n192.168.73.13")
	res, err := m.GetInterfaceAddresses(t.Context(), "06:ff:f7:8b:c3:95")
	require.NoError(t, err)
	require.Equal(t, InterfaceAddresses{
		IPv4s: []netip.Addr{netip.MustParseAddr("192.168.78.248"), netip.MustParseAddr("192.168.73.13")},
	}, res, "a missing ipv4-prefix lists no prefixes")

	set("ipv4-prefix", "192.168.77.112/28\n")
	res, err = m.GetInterfaceAddresses(t.Context(), "06:ff:f7:8b:c3:95")
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.77.112/28")}, res.IPv4Prefixes)

	res, err = m.GetInterfaceAddresses(t.Context(), "06:ff:f7:8b:c3:96")
	require.NoError(t, err)
	require.Equal(t, InterfaceAddresses{}, res, "an interface missing from the metadata lists nothing")

	set("local-ipv4s", "not-an-ip")
	_, err = m.GetInterfaceAddresses(t.Context(), "06:ff:f7:8b:c3:95")
	require.Error(t, err)
}
