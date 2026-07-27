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

func TestAutodetectFlavorEKS(t *testing.T) {
	t.Run("by-cluster-name", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"foo.us-west-2.eksctl.io": {
						Cluster: "foo.us-west-2.eksctl.io",
					},
				},
				CurrentContext: "foo.us-west-2.eksctl.io",
			},
			contextName: "foo.us-west-2.eksctl.io",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind)
	})

	t.Run("by-cluster-server", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"my-cluster": {
						Server: "https://ABCDEF1234567890.gr7.us-west-2.eks.amazonaws.com",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind, "Should detect EKS via cluster server URL")
	})

	t.Run("by-cluster-server-ipv6", func(t *testing.T) {
		c := &Client{
			Clientset: fake.NewSimpleClientset(),
			RawConfig: clientcmdapi.Config{
				Contexts: map[string]*clientcmdapi.Context{
					"my-cluster": {
						Cluster: "my-cluster",
					},
				},
				Clusters: map[string]*clientcmdapi.Cluster{
					"my-cluster": {
						Server: "https://ABCDEF1234567890.gr7.eks-cluster.us-west-2.api.aws",
					},
				},
				CurrentContext: "my-cluster",
			},
			contextName: "my-cluster",
		}
		flavor := c.AutodetectFlavor(context.Background())
		assert.Equal(t, KindEKS, flavor.Kind, "Should detect EKS via IPv6 cluster server URL")
	})
}
