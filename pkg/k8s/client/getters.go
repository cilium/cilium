// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Getters is a set of methods for retrieving common objects.
type Getters interface {
	GetSecrets(ctx context.Context, namespace, name string) (map[string][]byte, error)
}

// ClientsetGetters implements the Getters interface in terms of the clientset.
type ClientsetGetters struct {
	Clientset
}

// GetSecrets returns the secrets found in the given namespace and name.
func (cs *ClientsetGetters) GetSecrets(ctx context.Context, ns, name string) (map[string][]byte, error) {
	if !cs.IsEnabled() {
		return nil, fmt.Errorf("GetSecrets: No k8s, cannot access k8s secrets")
	}

	result, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}
