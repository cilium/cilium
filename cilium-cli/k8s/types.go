// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceClient is a common client interface for typed k8s resource clients.
type ResourceClient[T any] interface {
	Create(ctx context.Context, r *T, opts metav1.CreateOptions) (*T, error)
	Update(ctx context.Context, r *T, opts metav1.UpdateOptions) (*T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*T, error)
}
