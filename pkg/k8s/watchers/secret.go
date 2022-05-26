// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_entensions_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	tlsCrtAttribute = "tls.crt"
	tlsKeyAttribute = "tls.key"

	tlsFieldSelector = "type=kubernetes.io/tls"
)

func (k *K8sWatcher) tlsSecretInit(k8sClient kubernetes.Interface, namespace string, swgSecrets *lock.StoppableWaitGroup) {
	secretOptsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = tlsFieldSelector
	}

	apiGroup := resources.K8sAPIGroupSecretV1Core
	_, secretController := informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"secrets", namespace,
			secretOptsModifier,
		),
		&slim_corev1.Secret{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(apiGroup, metricSecret, resources.MetricCreate, valid, equal)
				}()
				if k8sSecret := k8s.ObjToV1Secret(obj); k8sSecret != nil {
					valid = true
					err := k.addK8sSecretV1(k8sSecret)
					k.K8sEventProcessed(metricSecret, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, metricSecret, resources.MetricUpdate, valid, equal) }()
				if oldSecret := k8s.ObjToV1Secret(oldObj); oldSecret != nil {
					if newSecret := k8s.ObjToV1Secret(newObj); newSecret != nil {
						valid = true
						if oldSecret.DeepEqual(newSecret) {
							equal = true
							return
						}
						err := k.updateK8sSecretV1(oldSecret, newSecret)
						k.K8sEventProcessed(metricSecret, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(apiGroup, metricSecret, resources.MetricDelete, valid, equal)
				}()
				k8sSecret := k8s.ObjToV1Secret(obj)
				if k8sSecret == nil {
					return
				}
				valid = true
				err := k.deleteK8sSecretV1(k8sSecret)
				k.K8sEventProcessed(metricSecret, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(k.stop, swgSecrets, secretController.HasSynced, resources.K8sAPIGroupSecretV1Core)
	go secretController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(apiGroup)
}

// addK8sSecretV1 performs Envoy upsert operation for newly added secret.
func (k *K8sWatcher) addK8sSecretV1(secret *slim_corev1.Secret) error {
	resource := envoy.Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{k8sToEnvoySecret(secret)},
	}
	return k.envoyConfigManager.UpsertEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
}

// updateK8sSecretV1 performs Envoy upsert operation for updated secret (if required).
func (k *K8sWatcher) updateK8sSecretV1(oldSecret, newSecret *slim_corev1.Secret) error {
	if oldSecret != nil && oldSecret.DeepEqual(newSecret) {
		return nil
	}
	resource := envoy.Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{k8sToEnvoySecret(newSecret)},
	}
	return k.envoyConfigManager.UpsertEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
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
	return k.envoyConfigManager.DeleteEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
}

// k8sToEnvoySecret converts k8s secret object to envoy TLS secret object
func k8sToEnvoySecret(secret *slim_corev1.Secret) *envoy_entensions_tls_v3.Secret {
	if secret == nil {
		return nil
	}
	return &envoy_entensions_tls_v3.Secret{
		Name: getEnvoySecretName(secret.GetNamespace(), secret.GetName()),
		Type: &envoy_entensions_tls_v3.Secret_TlsCertificate{
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
		},
	}
}

func getEnvoySecretName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
