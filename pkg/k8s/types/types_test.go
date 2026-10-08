// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestCiliumEndpointDeepEqualIncludesPodUID(t *testing.T) {
	endpoint := &CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "default",
			OwnerReferences: []slim_metav1.OwnerReference{
				{
					Kind: "Pod",
					UID:  k8sTypes.UID("old-pod-uid"),
				},
			},
		},
	}

	same := endpoint.DeepCopy()
	require.True(t, endpoint.DeepEqual(same))
	require.Equal(t, "old-pod-uid", endpoint.GetPodUID())

	changed := endpoint.DeepCopy()
	changed.OwnerReferences[0].UID = k8sTypes.UID("new-pod-uid")
	require.False(t, endpoint.DeepEqual(changed))
}
