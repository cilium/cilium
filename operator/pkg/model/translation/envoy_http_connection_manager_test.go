// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	httpConnectionManagerv3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

	require.Len(t, httpConnectionManager.GetHttpFilters(), 1)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[0].Name)

	require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
	require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
}
