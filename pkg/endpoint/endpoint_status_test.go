// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func TestGetCiliumEndpointStatus(t *testing.T) {
	s := setupEndpointSuite(t)

	e, err := NewEndpointFromChangeModel(context.TODO(), hivetest.Logger(t), nil, &MockEndpointBuildQueue{}, nil, s.orchestrator, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, s.mgr, ctmap.NewFakeGCRunner(), nil, &models.EndpointChangeRequest{
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
	}, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil, node.NewTestLocalNodeStore(node.LocalNode{}))
	require.NoError(t, err)

	status := e.GetCiliumEndpointStatus()

	require.Equal(t, int64(200), status.ID)
	require.Equal(t, string(models.EndpointStateWaitingDashForDashIdentity), status.State)
	require.Nil(t, status.Log)
	require.Equal(t, &models.EndpointIdentifiers{
		ContainerID:     "ContainerID",
		CniAttachmentID: "ContainerID",
		ContainerName:   "ContainerName",
		K8sNamespace:    "Namespace",
		K8sPodName:      "PodName",
		PodName:         "Namespace/PodName",
	}, status.ExternalIdentifiers)
	require.Nil(t, status.Identity)
	require.Equal(t, &v2.EndpointNetworking{Addressing: []*v2.AddressPair{{IPV4: "192.168.1.100", IPV6: "f00d::a10:0:0:abcd"}}, NodeIP: "<nil>"}, status.Networking)
	require.Equal(t, v2.EncryptionSpec{Key: 0}, status.Encryption)
	require.Equal(t, models.NamedPorts{}, status.NamedPorts)
	// ServiceAccount should be empty when no pod is set
	require.Empty(t, status.ServiceAccount)
}

func TestGetCiliumEndpointStatusWithServiceAccount(t *testing.T) {
	s := setupEndpointSuite(t)

	e, err := NewEndpointFromChangeModel(context.TODO(), hivetest.Logger(t), nil, &MockEndpointBuildQueue{}, nil, s.orchestrator, nil, nil, nil, nil, nil, nil, s.repo, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, s.mgr, ctmap.NewFakeGCRunner(), nil, &models.EndpointChangeRequest{
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
			"k8s:io.cilium.k8s.policy.serviceaccount=test-service-account",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil, node.NewTestLocalNodeStore(node.LocalNode{}))
	require.NoError(t, err)

	// Create a mock pod with ServiceAccount
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "PodName",
			Namespace: "Namespace",
		},
		Spec: slim_corev1.PodSpec{
			ServiceAccountName: "test-service-account",
		},
	}

	// Set the pod on the endpoint
	e.SetPod(pod)

	status := e.GetCiliumEndpointStatus()

	require.Equal(t, int64(200), status.ID)
	require.Equal(t, string(models.EndpointStateWaitingDashForDashIdentity), status.State)
	require.Nil(t, status.Log)
	require.Equal(t, &models.EndpointIdentifiers{
		ContainerID:     "ContainerID",
		CniAttachmentID: "ContainerID",
		ContainerName:   "ContainerName",
		K8sNamespace:    "Namespace",
		K8sPodName:      "PodName",
		PodName:         "Namespace/PodName",
	}, status.ExternalIdentifiers)
	require.Nil(t, status.Identity)
	require.Equal(t, &v2.EndpointNetworking{Addressing: []*v2.AddressPair{{IPV4: "192.168.1.100", IPV6: "f00d::a10:0:0:abcd"}}, NodeIP: "<nil>"}, status.Networking)
	require.Equal(t, v2.EncryptionSpec{Key: 0}, status.Encryption)
	require.Equal(t, models.NamedPorts{}, status.NamedPorts)
	// ServiceAccount should match the pod's ServiceAccountName
	require.Equal(t, "test-service-account", status.ServiceAccount)
}
