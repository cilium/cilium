// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
)

func TestGetCiliumEndpointStatus(t *testing.T) {
	p := createTestEndpointParams(t)
	m := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPv4: "192.168.1.100",
			IPv6: "f00d::a10:0:0:abcd",
		},
		ContainerID:  "ContainerID",
		K8sPodName:   "PodName",
		K8sNamespace: "Namespace",
		ID:           200,
		Labels: models.Labels{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, m, nil)
	require.NoError(t, err)

	status := e.GetCiliumEndpointStatus()

	require.Equal(t, int64(200), status.ID)
	require.Equal(t, string(models.EndpointStateWaitingDashForDashIdentity), status.State)
	require.Nil(t, status.Log)
	require.Equal(t, &models.EndpointIdentifiers{
		CniAttachmentID: "ContainerID",
	}, status.ExternalIdentifiers)
	require.Nil(t, status.Identity)
	require.Equal(t, &v2.EndpointNetworking{Addressing: []*v2.AddressPair{{IPV4: "192.168.1.100", IPV6: "f00d::a10:0:0:abcd"}}, NodeIP: "<nil>"}, status.Networking)
	require.Equal(t, v2.EncryptionSpec{Key: 0}, status.Encryption)
	require.Equal(t, models.NamedPorts{}, status.NamedPorts)
	// ServiceAccount should be empty when no pod is set
	require.Empty(t, status.ServiceAccount)
	require.Nil(t, status.Workload)
}

func TestCiliumEndpointStatusProxyNACK(t *testing.T) {
	repo := policy.NewPolicyRepository(hivetest.Logger(t), cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	p := createEndpointParams(t, nil, repo, nil)
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, newTestEndpointModel(200, StateWaitingForIdentity), nil)
	require.NoError(t, err)

	synctest.Test(t, func(t *testing.T) {
		nack := fmt.Errorf("%w: private proxy response details", proxytypes.ErrNackReceived)
		var firstFailure []models.EndpointStatusChange

		for _, step := range []struct {
			name    string
			err     error
			wantLog bool
		}{
			{name: "timeout", err: context.DeadlineExceeded},
			{name: "cancellation", err: context.Canceled},
			{name: "NACK", err: nack, wantLog: true},
			{name: "NACK retry", err: nack, wantLog: true},
			{name: "retry timeout", err: context.DeadlineExceeded, wantLog: true},
			{name: "successful regeneration"},
		} {
			time.Sleep(time.Second) // advance simulated synctest clock
			var regenErr error
			if step.err != nil {
				regenErr = newRegenerationError(regenerationFailureReasonProxyPolicyError, step.err)
			}
			e.updateRegenerationStatistics(&regenerationContext{}, regenErr)
			log := e.GetCiliumEndpointStatus().Log
			if !step.wantLog {
				require.Empty(t, log, step.name)
				continue
			}
			if firstFailure == nil {
				firstFailure = []models.EndpointStatusChange{{
					Code:      models.EndpointStatusChangeCodeFailed,
					Message:   "Envoy rejected an update required for endpoint policy. Regeneration will retry.",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}}
			}
			require.Equal(t, firstFailure, log, step.name)
		}
	})
}

func TestGetCiliumEndpointStatusWithServiceAccount(t *testing.T) {
	p := createTestEndpointParams(t)
	m := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPv4: "192.168.1.100",
			IPv6: "f00d::a10:0:0:abcd",
		},
		ContainerID:  "ContainerID",
		K8sPodName:   "PodName",
		K8sNamespace: "Namespace",
		ID:           200,
		Labels: models.Labels{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=test-service-account",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}
	e, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, m, nil)
	require.NoError(t, err)

	controller := true
	// Create a mock pod with ServiceAccount and workload metadata.
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:         "test-workload-7c9f55d4b9-abcde",
			GenerateName: "test-workload-7c9f55d4b9-",
			Namespace:    "Namespace",
			Labels: map[string]string{
				"pod-template-hash": "7c9f55d4b9",
			},
			OwnerReferences: []slim_metav1.OwnerReference{{
				Kind:       "ReplicaSet",
				Name:       "test-workload-7c9f55d4b9",
				Controller: &controller,
			}},
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
		CniAttachmentID: "ContainerID",
	}, status.ExternalIdentifiers)
	require.Nil(t, status.Identity)
	require.Equal(t, &v2.EndpointNetworking{Addressing: []*v2.AddressPair{{IPV4: "192.168.1.100", IPV6: "f00d::a10:0:0:abcd"}}, NodeIP: "<nil>"}, status.Networking)
	require.Equal(t, v2.EncryptionSpec{Key: 0}, status.Encryption)
	require.Equal(t, models.NamedPorts{}, status.NamedPorts)
	// ServiceAccount should match the pod's ServiceAccountName
	require.Equal(t, "test-service-account", status.ServiceAccount)
	require.Equal(t, &v2.EndpointWorkload{Name: "test-workload", Kind: "Deployment"}, status.Workload)
}
