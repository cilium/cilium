// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_entensions_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"

	"github.com/cilium/cilium/pkg/envoy"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	tlsCrtAttribute = "tls.crt"
	tlsKeyAttribute = "tls.key"

	// Key for CA certificate is fixed as 'ca.crt' even though is not as "standard"
	// as 'tls.crt' and 'tls.key' are via k8s tls secret type.
	caCrtAttribute = "ca.crt"
)

// addK8sSecretV1 performs Envoy upsert operation for newly added secret.
func (k *K8sWatcher) addK8sSecretV1(secret *slim_corev1.Secret) error {
	resource := envoy.Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{k8sToEnvoySecret(secret)},
	}
	return k.envoyXdsServer.UpsertEnvoyResources(context.TODO(), resource)
}

// updateK8sSecretV1 performs Envoy upsert operation for updated secret (if required).
func (k *K8sWatcher) updateK8sSecretV1(oldSecret, newSecret *slim_corev1.Secret) error {
	if oldSecret != nil && oldSecret.DeepEqual(newSecret) {
		return nil
	}
	resource := envoy.Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{k8sToEnvoySecret(newSecret)},
	}
	return k.envoyXdsServer.UpsertEnvoyResources(context.TODO(), resource)
}

// deleteK8sSecretV1 makes sure the related secret values in Envoy SDS is removed.
func (k *K8sWatcher) deleteK8sSecretV1(secret *slim_corev1.Secret) error {
	resource := envoy.Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{
			{
				// For deletion, only the name is required.
				Name: getEnvoySecretName(secret.GetNamespace(), secret.GetName()),
			},
		},
	}
	return k.envoyXdsServer.DeleteEnvoyResources(context.TODO(), resource)
}

// k8sToEnvoySecret converts k8s secret object to envoy TLS secret object
func k8sToEnvoySecret(secret *slim_corev1.Secret) *envoy_entensions_tls_v3.Secret {
	if secret == nil {
		return nil
	}
	envoySecret := &envoy_entensions_tls_v3.Secret{
		Name: getEnvoySecretName(secret.GetNamespace(), secret.GetName()),
	}

	if len(secret.Data[tlsCrtAttribute]) > 0 || len(secret.Data[tlsKeyAttribute]) > 0 {
		envoySecret.Type = &envoy_entensions_tls_v3.Secret_TlsCertificate{
			TlsCertificate: &envoy_entensions_tls_v3.TlsCertificate{
				CertificateChain: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[tlsCrtAttribute],
					},
				},
				PrivateKey: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[tlsKeyAttribute],
					},
				},
			},
		}
	} else if len(secret.Data[caCrtAttribute]) > 0 {
		envoySecret.Type = &envoy_entensions_tls_v3.Secret_ValidationContext{
			ValidationContext: &envoy_entensions_tls_v3.CertificateValidationContext{
				TrustedCa: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[caCrtAttribute],
					},
				},
				// TODO: Consider support for other ValidationContext config.
			},
		}
	}

	return envoySecret
}

func getEnvoySecretName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func uniq(arr []string) []string {
	keys := make(map[string]bool)
	for _, entry := range arr {
		keys[entry] = true
	}

	list := make([]string, 0, len(keys))
	for k := range keys {
		list = append(list, k)
	}
	return list
}
