// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// ServiceResolverCell provides a ServiceResolver instance to map DNS names
// matching Kubernetes services to the corresponding ClusterIP address, backed
// by a lazy resource.Store, which is only started on first access.
var ServiceResolverCell = cell.Module(
	"service-resolver",
	"Service DNS names to ClusterIP translator",

	cell.Provide(newServiceResolver),
)

var _ Resolver = (*ServiceResolver)(nil)

// ServiceResolver maps DNS names matching Kubernetes services to the
// corresponding ClusterIP address.
type ServiceResolver struct {
	start func()
	ready <-chan struct{}

	store resource.Store[*slim_corev1.Service]
}

func newServiceResolver(jg job.Group, services resource.Resource[*slim_corev1.Service]) *ServiceResolver {
	start := make(chan struct{})
	ready := make(chan struct{})

	sr := ServiceResolver{
		start: sync.OnceFunc(func() { close(start) }),
		ready: ready,
	}

	jg.Add(job.OneShot("service-reloader-initializer", func(ctx context.Context, health cell.Health) error {
		select {
		case <-ctx.Done():
			return nil // We are shutting down
		case <-start:
		}

		store, err := services.Store(ctx)
		if err != nil {
			return nil // We are shutting down
		}

		sr.store = store
		health.OK("Synchronized")
		close(ready)
		return nil
	}))

	return &sr
}

func (sr *ServiceResolver) Resolve(ctx context.Context, host string) (string, error) {
	nsname, err := ServiceURLToNamespacedName(host)
	if err != nil {
		// The host does not look like a k8s service DNS name
		return "", err
	}

	sr.start()

	select {
	case <-ctx.Done():
		// The context expired before the underlying store was ready
		return "", ctx.Err()
	case <-sr.ready:
	}

	svc, exists, err := sr.store.GetByKey(resource.Key{Namespace: nsname.Namespace, Name: nsname.Name})
	switch {
	case err != nil:
		return "", err
	case !exists:
		return "", k8serr.NewNotFound(slim_corev1.Resource("service"), nsname.String())
	}

	if _, err := netip.ParseAddr(svc.Spec.ClusterIP); err != nil {
		return "", fmt.Errorf("cannot parse ClusterIP address: %w", err)
	}

	return svc.Spec.ClusterIP, nil
}

func ServiceURLToNamespacedName(host string) (types.NamespacedName, error) {
	tokens := strings.Split(host, ".")
	if len(tokens) < 2 {
		return types.NamespacedName{}, fmt.Errorf("%s does not match the <name>.<namespace>(.svc) form", host)
	}

	if len(tokens) >= 3 && tokens[2] != "svc" {
		return types.NamespacedName{}, fmt.Errorf("%s does not match the <name>.<namespace>(.svc) form", host)
	}

	return types.NamespacedName{Namespace: tokens[1], Name: tokens[0]}, nil
}
