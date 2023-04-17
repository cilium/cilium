// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// Getters is a set of methods for retrieving common objects.
type Getters interface {
	GetSecrets(ctx context.Context, namespace, name string) (map[string][]byte, error)
	GetK8sNode(ctx context.Context, nodeName string) (*slim_corev1.Node, error)
	GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error)
}

// clientsetGetters implements the Getters interface in terms of the clientset.
type clientsetGetters struct {
	Clientset
}

// GetSecrets returns the secrets found in the given namespace and name.
func (cs *clientsetGetters) GetSecrets(ctx context.Context, ns, name string) (map[string][]byte, error) {
	if !cs.IsEnabled() {
		return nil, fmt.Errorf("GetSecrets: No k8s, cannot access k8s secrets")
	}

	result, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// GetK8sNode returns the node with the given nodeName.
func (cs *clientsetGetters) GetK8sNode(ctx context.Context, nodeName string) (*slim_corev1.Node, error) {
	if !cs.IsEnabled() {
		return nil, fmt.Errorf("GetK8sNode: No k8s, cannot access k8s nodes")
	}

	return cs.Slim().CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
}

// GetCiliumNode returns the CiliumNode with the given nodeName.
func (cs *clientsetGetters) GetCiliumNode(ctx context.Context, nodeName string) (*cilium_v2.CiliumNode, error) {
	if !cs.IsEnabled() {
		return nil, fmt.Errorf("GetK8sNode: No k8s, cannot access k8s nodes")
	}

	return cs.CiliumV2().CiliumNodes().Get(ctx, nodeName, metav1.GetOptions{})
}
