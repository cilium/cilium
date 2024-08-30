// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"io"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

func Test_k8sSecretToEnvoySecretTlsCertificate(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.crt": []byte{1, 2, 3},
			"tls.key": []byte{4, 5, 6},
		},
		Type: slim_corev1.SecretTypeTLS,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Equal(t, []byte{1, 2, 3}, envoySecret.GetTlsCertificate().GetCertificateChain().GetInlineBytes())
	require.Equal(t, []byte{4, 5, 6}, envoySecret.GetTlsCertificate().GetPrivateKey().GetInlineBytes())
}

func Test_k8sSecretToEnvoySecretValidationContext(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"ca.crt": []byte{1, 2, 3},
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Equal(t, []byte{1, 2, 3}, envoySecret.GetValidationContext().TrustedCa.GetInlineBytes())
	require.Nil(t, envoySecret.GetTlsCertificate())
}

func testSessionKey(i byte) []byte {
	b := make([]byte, 80)
	b[0] = i
	return b
}

func Test_k8sSecretToEnvoySecretTlsSessionKeys(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.sessionticket.key":   testSessionKey(0),
			"tls.sessionticket.key.1": testSessionKey(1),
			"tls.sessionticket.key.2": testSessionKey(2),
			"tls.sessionticket.key.3": testSessionKey(3),
			"tls.sessionticket.key.4": testSessionKey(4),
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Len(t, envoySecret.GetSessionTicketKeys().Keys, 5)

	require.Equal(t, testSessionKey(0), envoySecret.GetSessionTicketKeys().Keys[0].GetInlineBytes())
	require.Equal(t, testSessionKey(1), envoySecret.GetSessionTicketKeys().Keys[1].GetInlineBytes())
	require.Equal(t, testSessionKey(2), envoySecret.GetSessionTicketKeys().Keys[2].GetInlineBytes())
	require.Equal(t, testSessionKey(3), envoySecret.GetSessionTicketKeys().Keys[3].GetInlineBytes())
	require.Equal(t, testSessionKey(4), envoySecret.GetSessionTicketKeys().Keys[4].GetInlineBytes())

	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetValidationContext())
}

func Test_k8sSecretToEnvoySecretTlsSessionKeys_FirstKeyMandatory(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.sessionticket.key.1": testSessionKey(1),
			"tls.sessionticket.key.2": testSessionKey(2),
			"tls.sessionticket.key.3": testSessionKey(3),
			"tls.sessionticket.key.4": testSessionKey(4),
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)

	require.Nil(t, envoySecret.GetSessionTicketKeys())
	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetValidationContext())
}

func Test_k8sSecretToEnvoySecretTlsSessionKeys_Max10Keys(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.sessionticket.key":    testSessionKey(0),
			"tls.sessionticket.key.1":  testSessionKey(1),
			"tls.sessionticket.key.2":  testSessionKey(2),
			"tls.sessionticket.key.3":  testSessionKey(3),
			"tls.sessionticket.key.4":  testSessionKey(4),
			"tls.sessionticket.key.5":  testSessionKey(5),
			"tls.sessionticket.key.6":  testSessionKey(6),
			"tls.sessionticket.key.7":  testSessionKey(7),
			"tls.sessionticket.key.8":  testSessionKey(8),
			"tls.sessionticket.key.9":  testSessionKey(9),
			"tls.sessionticket.key.10": testSessionKey(10),
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)

	require.Len(t, envoySecret.GetSessionTicketKeys().Keys, 10)

	require.Equal(t, testSessionKey(0), envoySecret.GetSessionTicketKeys().Keys[0].GetInlineBytes())
	require.Equal(t, testSessionKey(1), envoySecret.GetSessionTicketKeys().Keys[1].GetInlineBytes())
	require.Equal(t, testSessionKey(2), envoySecret.GetSessionTicketKeys().Keys[2].GetInlineBytes())
	require.Equal(t, testSessionKey(3), envoySecret.GetSessionTicketKeys().Keys[3].GetInlineBytes())
	require.Equal(t, testSessionKey(4), envoySecret.GetSessionTicketKeys().Keys[4].GetInlineBytes())
	require.Equal(t, testSessionKey(5), envoySecret.GetSessionTicketKeys().Keys[5].GetInlineBytes())
	require.Equal(t, testSessionKey(6), envoySecret.GetSessionTicketKeys().Keys[6].GetInlineBytes())
	require.Equal(t, testSessionKey(7), envoySecret.GetSessionTicketKeys().Keys[7].GetInlineBytes())
	require.Equal(t, testSessionKey(8), envoySecret.GetSessionTicketKeys().Keys[8].GetInlineBytes())
	require.Equal(t, testSessionKey(9), envoySecret.GetSessionTicketKeys().Keys[9].GetInlineBytes())

	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetValidationContext())
}

func Test_k8sSecretToEnvoySecretTlsSessionKeys_SkipAdditionalKeysOnMainKeySizeIssue(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.sessionticket.key":   []byte{}, // not 80 bytes
			"tls.sessionticket.key.1": testSessionKey(1),
			"tls.sessionticket.key.2": testSessionKey(2),
			"tls.sessionticket.key.3": testSessionKey(3),
			"tls.sessionticket.key.4": testSessionKey(4),
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)

	require.Nil(t, envoySecret.GetSessionTicketKeys())
	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetValidationContext())
}

func Test_k8sSecretToEnvoySecretTlsSessionKeys_SkipAdditionalKeyOnSizeIssue(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.sessionticket.key":    testSessionKey(0),
			"tls.sessionticket.key.1":  testSessionKey(1),
			"tls.sessionticket.key.2":  testSessionKey(2),
			"tls.sessionticket.key.3":  []byte{}, // not 80 bytes -> will be skipped
			"tls.sessionticket.key.4":  testSessionKey(4),
			"tls.sessionticket.key.5":  testSessionKey(5),
			"tls.sessionticket.key.6":  testSessionKey(6),
			"tls.sessionticket.key.7":  make([]byte, 90), // not 80 bytes -> will be skipped
			"tls.sessionticket.key.8":  testSessionKey(8),
			"tls.sessionticket.key.9":  testSessionKey(9),
			"tls.sessionticket.key.10": testSessionKey(10),
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)

	require.Len(t, envoySecret.GetSessionTicketKeys().Keys, 8)

	require.Equal(t, testSessionKey(0), envoySecret.GetSessionTicketKeys().Keys[0].GetInlineBytes())
	require.Equal(t, testSessionKey(1), envoySecret.GetSessionTicketKeys().Keys[1].GetInlineBytes())
	require.Equal(t, testSessionKey(2), envoySecret.GetSessionTicketKeys().Keys[2].GetInlineBytes())
	require.Equal(t, testSessionKey(4), envoySecret.GetSessionTicketKeys().Keys[3].GetInlineBytes())
	require.Equal(t, testSessionKey(5), envoySecret.GetSessionTicketKeys().Keys[4].GetInlineBytes())
	require.Equal(t, testSessionKey(6), envoySecret.GetSessionTicketKeys().Keys[5].GetInlineBytes())
	require.Equal(t, testSessionKey(8), envoySecret.GetSessionTicketKeys().Keys[6].GetInlineBytes())
	require.Equal(t, testSessionKey(9), envoySecret.GetSessionTicketKeys().Keys[7].GetInlineBytes())

	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetValidationContext())
}

func Test_k8sSecretToEnvoySecretGeneric(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"generic": []byte{1, 2, 3},
		},
		Type: slim_corev1.SecretTypeOpaque,
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Equal(t, []byte{1, 2, 3}, envoySecret.GetGenericSecret().Secret.GetInlineBytes())
	require.Nil(t, envoySecret.GetValidationContext())
	require.Nil(t, envoySecret.GetTlsCertificate())
	require.Nil(t, envoySecret.GetSessionTicketKeys())
}

func TestHandleSecretEvent(t *testing.T) {
	tests := []struct {
		name                 string
		secret               *slim_corev1.Secret
		kind                 resource.EventKind
		currentNodeLabels    map[string]string
		newNodeLabels        map[string]string
		xdsShouldReturnError bool
		expectedError        bool
		expectedUpserts      int
		expectedDeletions    int
	}{
		{
			name:              "upserted secret should be upserted in xDS",
			secret:            testSecret(),
			kind:              resource.Upsert,
			expectedError:     false,
			expectedUpserts:   1,
			expectedDeletions: 0,
		},
		{
			name:              "deleted secret should be deleted in xDS",
			secret:            testSecret(),
			kind:              resource.Delete,
			expectedError:     false,
			expectedUpserts:   0,
			expectedDeletions: 1,
		},
		{
			name:              "sync event should not be handled",
			secret:            testSecret(),
			kind:              resource.Sync,
			expectedError:     false,
			expectedUpserts:   0,
			expectedDeletions: 0,
		},
		{
			name:              "upserting a nil secret should result in an error",
			secret:            nil,
			kind:              resource.Upsert,
			expectedError:     true,
			expectedUpserts:   0,
			expectedDeletions: 0,
		},
		{
			name:              "delete event with empty key namespace and/or name should result in an error",
			secret:            nil,
			kind:              resource.Delete,
			expectedError:     true,
			expectedUpserts:   0,
			expectedDeletions: 0,
		},
		{
			name:                 "upsert errors of xDS server should be returned",
			secret:               testSecret(),
			kind:                 resource.Upsert,
			xdsShouldReturnError: true,
			expectedError:        true,
			expectedUpserts:      0,
			expectedDeletions:    0,
		},
		{
			name:                 "delete errors of xDS server should be returned",
			secret:               testSecret(),
			kind:                 resource.Delete,
			xdsShouldReturnError: true,
			expectedError:        true,
			expectedUpserts:      0,
			expectedDeletions:    0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)

			xdsServer := &fakeXdsServer{
				returnError: tc.xdsShouldReturnError,
			}

			syncer := newSecretSyncer(logger, xdsServer)

			doneCalled := false
			var doneError error

			doneFunc := func(err error) {
				doneCalled = true
				doneError = err
			}

			err := syncer.handleSecretEvent(context.Background(), testEvent(tc.secret, tc.kind, doneFunc))
			assert.Equal(t, tc.expectedError, err != nil, "Expected returned error should match")

			assert.True(t, doneCalled, "Done must be called on the event in all cases")
			assert.Equal(t, tc.expectedError, doneError != nil, "Expected done error should match")

			assert.Equal(t, tc.expectedUpserts, xdsServer.nrOfUpserts)
			assert.Equal(t, tc.expectedDeletions, xdsServer.nrOfDeletions)
			assert.Equal(t, 0, xdsServer.nrOfUpdates, "Secret sync should never use update functionality")
		})
	}
}

func testEvent(secret *slim_corev1.Secret, eventKind resource.EventKind, eventDone func(err error)) resource.Event[*slim_corev1.Secret] {
	event := resource.Event[*slim_corev1.Secret]{}
	if secret != nil {
		event.Key = resource.NewKey(secret)
	}
	event.Object = secret
	event.Kind = eventKind
	event.Done = eventDone

	return event
}

func testSecret() *slim_corev1.Secret {
	return &slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: "test",
			Name:      "test",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.crt": []byte("content"),
		},
		Type: "kubernetes.io/tls",
	}
}

type fakeXdsServer struct {
	nrOfDeletions int
	returnError   bool
	nrOfUpdates   int
	nrOfUpserts   int
}

var _ XDSServer = &fakeXdsServer{}

func (r *fakeXdsServer) Reset() {
	r.nrOfUpdates = 0
	r.nrOfUpserts = 0
	r.nrOfDeletions = 0
}

func (r *fakeXdsServer) UpdateEnvoyResources(ctx context.Context, old Resources, new Resources) error {
	if r.returnError {
		return errors.New("failed to update envoy resources")
	}

	r.nrOfUpdates++
	return nil
}

func (r *fakeXdsServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	if r.returnError {
		return errors.New("failed to delete envoy resources")
	}

	r.nrOfDeletions++
	return nil
}

func (r *fakeXdsServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	if r.returnError {
		return errors.New("failed to upsert envoy resources")
	}

	r.nrOfUpserts++
	return nil
}

func (*fakeXdsServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddAdminListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*fakeXdsServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (*fakeXdsServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	panic("unimplemented")
}

func (*fakeXdsServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced bool, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	panic("unimplemented")
}
