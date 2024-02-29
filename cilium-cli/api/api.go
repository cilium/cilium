// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"

	"github.com/cilium/cilium-cli/k8s"
)

// key is a context.Context value key type. It's unexported to avoid key collisions.
type key int

const (
	namespaceKey key = iota
	k8sClientKey
)

// SetNamespaceContextValue stores a namespace string as a context value and
// returns the resulting context. You can access the namespace by calling
// GetNamespaceContextValue.
func SetNamespaceContextValue(ctx context.Context, namespace string) context.Context {
	return context.WithValue(ctx, namespaceKey, namespace)
}

// SetK8sClientContextValue stores a namespace string as a context value and
// returns the resulting context. You can access the namespace by calling
// GetK8sClientContextValue.
func SetK8sClientContextValue(ctx context.Context, client *k8s.Client) context.Context {
	return context.WithValue(ctx, k8sClientKey, client)
}

// GetNamespaceContextValue retrieves the namespace from a context that was
// stored by SetNamespaceContextValue.
func GetNamespaceContextValue(ctx context.Context) (string, bool) {
	namespace, ok := ctx.Value(namespaceKey).(string)
	return namespace, ok
}

// GetK8sClientContextValue retrieves the k8s.Client from a context that was
// stored by SetK8sClientContextValue.
func GetK8sClientContextValue(ctx context.Context) (*k8s.Client, bool) {
	client, ok := ctx.Value(k8sClientKey).(*k8s.Client)
	return client, ok
}
