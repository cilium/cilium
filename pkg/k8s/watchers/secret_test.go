// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_k8sToEnvoySecret(t *testing.T) {
	envoySecret := k8sToEnvoySecret(&slim_corev1.Secret{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "dummy-secret",
			Namespace: "dummy-namespace",
		},
		Data: map[string]slim_corev1.Bytes{
			"tls.crt": []byte{1, 2, 3},
			"tls.key": []byte{4, 5, 6},
		},
		Type: "kubernetes.io/tls",
	})

	require.Equal(t, "dummy-namespace/dummy-secret", envoySecret.Name)
	require.Equal(t, []byte{1, 2, 3}, envoySecret.GetTlsCertificate().GetCertificateChain().GetInlineBytes())
	require.Equal(t, []byte{4, 5, 6}, envoySecret.GetTlsCertificate().GetPrivateKey().GetInlineBytes())
}
