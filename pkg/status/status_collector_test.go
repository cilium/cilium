// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/fqdn/service"
	k8stest "github.com/cilium/cilium/pkg/k8s/client/testutils"
)

func TestGetStatusStandaloneDNSProxyReadiness(t *testing.T) {
	for _, tt := range []struct {
		name   string
		server *service.FQDNDataServer
		state  string
	}{
		{name: "disabled", state: models.StatusStateOk},
		{name: "not listening", server: &service.FQDNDataServer{}, state: models.StatusStateFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			client, clientset := k8stest.NewFakeClientset(logger)
			client.Disable()
			collector := &statusCollector{
				allProbesInitialized: true,
				statusCollector:      newCollector(logger, Config{}),
				statusParams: statusParams{
					Clientset:      clientset,
					FQDNDataServer: tt.server,
				},
			}

			for _, brief := range []bool{false, true} {
				for _, requireK8sConnectivity := range []bool{false, true} {
					status := collector.GetStatus(brief, requireK8sConnectivity)
					require.Equal(t, tt.state, status.Cilium.State)
					if tt.server != nil {
						require.Contains(t, status.Cilium.Msg, "Standalone DNS proxy gRPC server is not ready")
					}
				}
			}
		})
	}
}
