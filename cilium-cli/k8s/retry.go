// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// writeAttempts caps how many times retryWrite sends a write that the API server answers with a Timeout.
const writeAttempts = 4

// writeRetryBackoff is the delay before the first retry, doubled before each next one.
const writeRetryBackoff = time.Second

// retryWrite repeats a write of the object called name while the API server answers it with a Timeout.
func retryWrite[T any](ctx context.Context, name string, write func() (T, error), get func() (T, error)) (T, error) {
	timedOut := false
	backoff := writeRetryBackoff
	for attempt := 1; ; attempt++ {
		obj, err := write()
		switch {
		case err == nil:
			return obj, nil
		case timedOut && get != nil && k8serrors.IsAlreadyExists(err):
			// The attempt that timed out created the object.
			return get()
		case name == "" || !k8serrors.IsTimeout(err) || attempt == writeAttempts:
			return obj, err
		}
		timedOut = true
		select {
		case <-ctx.Done():
			return obj, err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

type typedCreator[T any] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
}

func createRetry[T metav1.Object](ctx context.Context, client typedCreator[T], obj T, opts metav1.CreateOptions) (T, error) {
	return retryWrite(ctx, obj.GetName(),
		func() (T, error) { return client.Create(ctx, obj, opts) },
		func() (T, error) { return client.Get(ctx, obj.GetName(), metav1.GetOptions{}) })
}
