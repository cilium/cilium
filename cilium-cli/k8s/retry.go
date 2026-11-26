// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type typedCreator[T any] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
}

func createRetry[T metav1.Object](ctx context.Context, client typedCreator[T], obj T, opts metav1.CreateOptions) (T, error) {
	return client.Create(ctx, obj, opts)
}
