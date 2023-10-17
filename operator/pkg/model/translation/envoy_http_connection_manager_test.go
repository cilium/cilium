// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	httpConnectionManagerv3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	operatorOption "github.com/cilium/cilium/operator/option"
)

func TestNewHTTPConnectionManager(t *testing.T) {
	res, err := NewHTTPConnectionManager("dummy-name", "dummy-route-name")
	require.Nil(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)

	require.Nil(t, err)

	require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
	require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
		Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
	}, httpConnectionManager.GetRouteSpecifier())

	require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
	require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

	require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
	require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
}

func TestNewHTTPConnectionManagerWithXffNumTrustedHops(t *testing.T) {
	res, err := NewHTTPConnectionManager("dummy-name", "dummy-route-name", WithXffNumTrustedHops())
	require.Nil(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)
	require.Nil(t, err)

	// Default value is 0
	require.Equal(t, uint32(0), httpConnectionManager.XffNumTrustedHops)

	var xffNumTrustedHops = uint32(1)

	operatorOption.Config.IngressProxyXffNumTrustedHops = xffNumTrustedHops

	defer func() {
		// Restore the value after the test
		operatorOption.Config.IngressProxyXffNumTrustedHops = uint32(0)
	}()
	res, err = NewHTTPConnectionManager("dummy-name", "dummy-route-name", WithXffNumTrustedHops())
	require.Nil(t, err)

	httpConnectionManager = &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)
	require.Nil(t, err)
	// Now it should be 1
	require.Equal(t, xffNumTrustedHops, httpConnectionManager.XffNumTrustedHops)
}
