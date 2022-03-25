// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	tlsCrtAttribute = "tls.crt"
	tlsKeyAttribute = "tls.key"
)

func (k *K8sWatcher) tlsSecretInit(k8sClient kubernetes.Interface, swgSecrets *lock.StoppableWaitGroup) {
	secretOptsModifier := func(options *metav1.ListOptions) {
		options.FieldSelector = "type=kubernetes.io/tls"
	}

	_, secretController := informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"secrets", corev1.NamespaceAll,
			secretOptsModifier,
		),
		&slim_corev1.Secret{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricSecret, metricCreate, valid, equal) }()
				if k8sSecret := k8s.ObjToV1Secret(obj); k8sSecret != nil {
					valid = true
					err := k.addK8sSecretV1(k8sSecret)
					k.K8sEventProcessed(metricSecret, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricSecret, metricUpdate, valid, equal) }()
				if oldk8sSecret := k8s.ObjToV1Secret(oldObj); oldk8sSecret != nil {
					if newk8sSecret := k8s.ObjToV1Secret(newObj); newk8sSecret != nil {
						log.Infof("new secret %+v", newk8sSecret)
						valid = true
						if oldk8sSecret.DeepEqual(newk8sSecret) {
							equal = true
							return
						}

						err := k.updateK8sSecretV1(oldk8sSecret, newk8sSecret)
						k.K8sEventProcessed(metricSecret, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricSecret, metricDelete, valid, equal) }()
				k8sSecret := k8s.ObjToV1Secret(obj)
				if k8sSecret == nil {
					return
				}
				valid = true
				err := k.deleteK8sSecretV1(k8sSecret)
				k.K8sEventProcessed(metricSecret, metricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(k.stop, swgSecrets, secretController.HasSynced, K8sAPIGroupSecretV1Core)
	go secretController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(K8sAPIGroupSecretV1Core)
}

func (k *K8sWatcher) addK8sSecretV1(secret *slim_corev1.Secret) error {
	resource := envoy.Resources{
		Secrets: []*envoy_config_tls.Secret{k8sToEnvoySecret(secret)},
	}
	return k.envoyConfigManager.UpsertEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
}

func (k *K8sWatcher) updateK8sSecretV1(oldSecret, newSecret *slim_corev1.Secret) error {
	if oldSecret != nil && oldSecret.DeepEqual(newSecret) {
		return nil
	}
	resource := envoy.Resources{
		Secrets: []*envoy_config_tls.Secret{k8sToEnvoySecret(newSecret)},
	}
	return k.envoyConfigManager.UpsertEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
}

func (k *K8sWatcher) deleteK8sSecretV1(secret *slim_corev1.Secret) error {
	resource := envoy.Resources{
		Secrets: []*envoy_config_tls.Secret{k8sToEnvoySecret(secret)},
	}
	return k.envoyConfigManager.DeleteEnvoyResources(context.TODO(), resource, k.envoyConfigManager)
}

func k8sToEnvoySecret(secret *slim_corev1.Secret) *envoy_config_tls.Secret {
	if secret == nil {
		return nil
	}
	return &envoy_config_tls.Secret{
		Name: fmt.Sprintf("%s/%s", secret.GetNamespace(), secret.GetName()),
		Type: &envoy_config_tls.Secret_TlsCertificate{
			TlsCertificate: &envoy_config_tls.TlsCertificate{
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
