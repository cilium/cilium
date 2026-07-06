// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestAutodetectFlavorGKE(t *testing.T) {
	t.Run("by-cluster-name", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"gke_project_zone_cluster": {
						Cluster: "gke_project_zone_cluster",
					},
				},
				CurrentContext: "gke_project_zone_cluster",
			},
			contextName: "gke_project_zone_cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindGKE, flavor.Kind)
	})

	t.Run("by-node-label", func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset(
			&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "gke-node-1",
					Labels: map[string]string{
						"cloud.google.com/gke-nodepool": "default-pool",
					},
				},
			},
		)

		c := &Client{
			Clientset: k8sClient,
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindGKE, flavor.Kind, "Should detect GKE via node label")
	})
}

func TestGetAPIServerHostAndPort(t *testing.T) {
	t.Run("defaults HTTPS port", func(t *testing.T) {
		c := &Client{
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"test": {Cluster: "test"},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"test": {Server: "https://api.example.test"},
				},
				CurrentContext: "test",
			},
			contextName: "test",
		}

		host, port := c.GetAPIServerHostAndPort()
		assert.Equal(t, "api.example.test", host)
		assert.Equal(t, "443", port)
	})

	t.Run("preserves explicit port", func(t *testing.T) {
		c := &Client{
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"test": {Cluster: "test"},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"test": {Server: "https://127.0.0.1:6443"},
				},
				CurrentContext: "test",
			},
			contextName: "test",
		}

		host, port := c.GetAPIServerHostAndPort()
		assert.Equal(t, "127.0.0.1", host)
		assert.Equal(t, "6443", port)
	})
}
