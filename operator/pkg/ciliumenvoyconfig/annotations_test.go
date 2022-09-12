// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"testing"

	http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_grpcHttpConnectionManagerMutator(t *testing.T) {
	input := &http_connection_manager_v3.HttpConnectionManager{}

	t.Run("mutate upgradeConfigs", func(t *testing.T) {
		res := grpcHttpConnectionManagerMutator(&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{},
		})(input)
		require.NotNil(t, res)
		require.NotNil(t, res.UpgradeConfigs)
	})
}
