// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func (s *EndpointSuite) TestGetCiliumEndpointStatus(c *C) {
	e, err := NewEndpointFromChangeModel(context.TODO(), s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, s.mgr, &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: "192.168.1.100",
			IPV6: "f00d::a10:0:0:abcd",
		},
		ContainerID:   "ContainerID",
		ContainerName: "ContainerName",
		K8sPodName:    "PodName",
		K8sNamespace:  "Namespace",
		ID:            200,
		Labels: models.Labels{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	})
	require.Nil(c, err)

	status := e.GetCiliumEndpointStatus()

	require.Equal(c, int64(200), status.ID)
	require.Equal(c, string(models.EndpointStateWaitingDashForDashIdentity), status.State)
	require.Nil(c, status.Log)
	require.Equal(c, &models.EndpointIdentifiers{
		ContainerID:     "ContainerID",
		CniAttachmentID: "ContainerID",
		ContainerName:   "ContainerName",
		K8sNamespace:    "Namespace",
		K8sPodName:      "PodName",
		PodName:         "Namespace/PodName",
	}, status.ExternalIdentifiers)
	require.Nil(c, status.Identity)
	require.Equal(c, &v2.EndpointNetworking{Addressing: []*v2.AddressPair{{IPV4: "192.168.1.100", IPV6: "f00d::a10:0:0:abcd"}}, NodeIP: "<nil>"}, status.Networking)
	require.Equal(c, v2.EncryptionSpec{Key: 0}, status.Encryption)
	require.Equal(c, models.NamedPorts{}, status.NamedPorts)
}
