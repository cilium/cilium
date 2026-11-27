// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"errors"
	"time"

	"helm.sh/helm/v4/pkg/kube"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/resource"
)

// helmReleaseAnnotations are the annotations through which Helm marks the release that owns a resource.
var helmReleaseAnnotations = []string{"meta.helm.sh/release-name", "meta.helm.sh/release-namespace"}

// writeAttempts caps how many times retryWrite sends a write that the API server answers with a Timeout.
const writeAttempts = 4

// writeRetryBackoff is the delay before the first retry, doubled before each next one.
const writeRetryBackoff = time.Second

// helmCreateRetryBudget bounds the retries of one Helm Create call, after which Create sends each remaining resource once.
const helmCreateRetryBudget = 5 * time.Minute

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

// helmKubeClient creates Helm's resources one at a time, so that retryWrite repeats only the create that timed out.
type helmKubeClient struct {
	*kube.Client
}

func (c *helmKubeClient) Create(resources kube.ResourceList, options ...kube.ClientCreateOption) (*kube.Result, error) {
	if len(resources) == 0 {
		return c.Client.Create(resources, options...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helmCreateRetryBudget)
	defer cancel()
	var errs []error
	for _, info := range resources {
		_, err := retryWrite(ctx, info.Name,
			func() (*kube.Result, error) { return c.Client.Create(kube.ResourceList{info}, options...) },
			func() (*kube.Result, error) { return nil, refreshOwned(info) })
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &kube.Result{Created: resources}, nil
}

// refreshOwned loads the existing object into info if it carries the Helm release annotations of the object sent.
func refreshOwned(info *resource.Info) error {
	obj, err := resource.NewHelper(info.Client, info.Mapping).Get(info.Namespace, info.Name)
	if err != nil {
		return err
	}
	sent, err := meta.Accessor(info.Object)
	if err != nil {
		return err
	}
	found, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	for _, key := range helmReleaseAnnotations {
		if found.GetAnnotations()[key] != sent.GetAnnotations()[key] {
			return k8serrors.NewAlreadyExists(info.Mapping.Resource.GroupResource(), info.Name)
		}
	}
	return info.Refresh(obj, true)
}
