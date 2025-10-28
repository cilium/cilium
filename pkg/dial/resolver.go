// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"fmt"
	"iter"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// ServiceResolverCell provides a ServiceResolver instance to map DNS names
// matching Kubernetes services to the corresponding ClusterIP address
// using the LB frontends table.
var ServiceResolverCell = cell.Module(
	"service-resolver",
	"Service DNS names to ClusterIP translator",

	cell.Provide(newLBServiceResolver),
)

// ResourceServiceResolverCell provides a ServiceResolver instance to map DNS names
// matching Kubernetes services to the corresponding ClusterIP address using the
// services resource. Used by the operator.
var ResourceServiceResolverCell = cell.Module(
	"service-resolver",
	"Service DNS names to ClusterIP translator",

	cell.Provide(newResourceServiceResolver),
)

// lbServiceResolver maps DNS names matching Kubernetes services to the
// corresponding ClusterIP address using Resource[*slim_corev1.Service].
// Used by the operator.
type resourceServiceResolver struct {
	start func()
	ready <-chan struct{}

	store resource.Store[*slim_corev1.Service]
}

func newResourceServiceResolver(jg job.Group, services resource.Resource[*slim_corev1.Service]) Resolver {
	start := make(chan struct{})
	ready := make(chan struct{})

	sr := resourceServiceResolver{
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

func (sr *resourceServiceResolver) Resolve(ctx context.Context, host, port string) (string, string) {
	return sr.resolve(ctx, host), port
}

func (sr *resourceServiceResolver) resolve(ctx context.Context, host string) string {
	nsname, err := ServiceURLToNamespacedName(host)
	if err != nil {
		// The host does not look like a k8s service DNS name
		return host
	}

	sr.start()

	select {
	case <-ctx.Done():
		// The context expired before the underlying store was ready
		return host
	case <-sr.ready:
	}

	svc, exists, err := sr.store.GetByKey(resource.Key{Namespace: nsname.Namespace, Name: nsname.Name})
	if err != nil || !exists {
		// We could not find a match for this service
		return host
	}

	if _, err := netip.ParseAddr(svc.Spec.ClusterIP); err != nil {
		// The ClusterIP is not a valid IP address (e.g., headless service)
		return host
	}

	return svc.Spec.ClusterIP
}

var _ Resolver = (*lbServiceResolver)(nil)

// lbServiceResolver maps DNS names matching Kubernetes services to the
// corresponding ClusterIP address using Table[*Frontend].
type lbServiceResolver struct {
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]
}

func newLBServiceResolver(jg job.Group, db *statedb.DB, frontends statedb.Table[*loadbalancer.Frontend]) Resolver {
	return &lbServiceResolver{
		db:        db,
		frontends: frontends,
	}
}

func (sr *lbServiceResolver) Resolve(ctx context.Context, host, port string) (string, string) {
	return sr.resolve(ctx, host), port
}

func (sr *lbServiceResolver) resolve(ctx context.Context, host string) string {
	nsname, err := ServiceURLToNamespacedName(host)
	if err != nil {
		// The host does not look like a k8s service DNS name
		return host
	}

	// Wait for the frontends table to be initialized from k8s. We can't check that
	// the table has been initialized by all initializers since at least ClusterMesh
	// uses [Resolve] to look up KVStore address.
	txn := sr.db.ReadTxn()
	init, waitInit := sr.frontends.Initialized(txn)
	for !init {
		pending := sr.frontends.PendingInitializers(txn)
		if !slices.ContainsFunc(pending, func(s string) bool { return strings.HasPrefix(s, reflectors.K8sInitializerPrefix) }) {
			break
		}
		select {
		case <-ctx.Done():
			return host
		case <-waitInit:
			init = true
		case <-time.After(100 * time.Millisecond):
		}
		txn = sr.db.ReadTxn()
	}

	fes := sr.frontends.List(
		txn,
		loadbalancer.FrontendByServiceName(loadbalancer.NewServiceName(nsname.Namespace, nsname.Name)))

	for fe := range fes {
		if fe.Type == loadbalancer.SVCTypeClusterIP {
			return fe.Address.Addr().String()
		}
	}

	// We could not find a ClusterIP frontend for this service
	return host
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

var _ Resolver = (*ServiceBackendResolver)(nil)

type ServiceBackendResolver struct {
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]

	ignoredInitializers []string

	// affinityCache is leveraged to preserve backend affinity when the resolver
	// is invoked multiple times for the same frontend. Indeed, this resolver is
	// intended to be used for the clustermesh-apiserver service, and each sidecar
	// etcd replica is different (from an etcd standpoint, even if they eventually
	// contain the same data), and connecting to a different one means that we need
	// to do a full synchronization again, which is expensive. We do not explicitly
	// collect stale entries, as we only ever expect a single one in the vast
	// majority of scenarios (and a handful at most in the others).
	mu            lock.Mutex
	affinityCache map[loadbalancer.L3n4Addr]loadbalancer.L3n4Addr
}

func ServiceBackendResolverFactory(ignoredInitializers ...string) func(db *statedb.DB, fes statedb.Table[*loadbalancer.Frontend]) *ServiceBackendResolver {
	return func(db *statedb.DB, fes statedb.Table[*loadbalancer.Frontend]) *ServiceBackendResolver {
		return &ServiceBackendResolver{
			db: db, frontends: fes,
			ignoredInitializers: ignoredInitializers,
			affinityCache:       make(map[loadbalancer.L3n4Addr]loadbalancer.L3n4Addr),
		}
	}
}

func (sr *ServiceBackendResolver) Resolve(ctx context.Context, host, port string) (string, string) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host, port
	}

	po, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return host, port
	}

	if err := sr.waitForInit(ctx); err != nil {
		return host, port
	}

	fe := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP, cmtypes.AddrClusterFrom(addr, 0),
		uint16(po), loadbalancer.ScopeExternal,
	)

	got := sr.resolve(fe)
	if got == nil {
		return host, port
	}

	return got.Addr().String(), strconv.FormatInt(int64(got.Port()), 10)
}

func (sr *ServiceBackendResolver) waitForInit(ctx context.Context) error {
	init, wait := sr.frontends.Initialized(sr.db.ReadTxn())
	if init {
		return nil
	}

	for {
		// We cannot just wait on full initialization of the table, as the
		// purpose of this resolver is to break a circular dependency that
		// would prevent it. Hence, let's periodically check the pending
		// initializers, and proceed if only expected ones are remaining.
		if initialized := !slices.ContainsFunc(
			sr.frontends.PendingInitializers(sr.db.ReadTxn()),
			func(init string) bool { return !slices.Contains(sr.ignoredInitializers, init) },
		); initialized {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-wait:
			return nil

		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (sr *ServiceBackendResolver) resolve(addr loadbalancer.L3n4Addr) (got *loadbalancer.L3n4Addr) {
	fe, _, found := sr.frontends.Get(sr.db.ReadTxn(), loadbalancer.FrontendByAddress(addr))
	if !found {
		return nil
	}

	bes := statedb.Collect(
		statedb.Map(
			statedb.Filter(
				iter.Seq2[loadbalancer.BackendParams, statedb.Revision](fe.Backends),
				func(bep loadbalancer.BackendParams) bool {
					return bep.State == loadbalancer.BackendStateActive && !bep.Unhealthy
				},
			),
			func(bep loadbalancer.BackendParams) loadbalancer.L3n4Addr {
				return bep.Address
			},
		),
	)

	if len(bes) == 0 {
		return nil
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Preserve affinity, in case the backend is still available
	prev, ok := sr.affinityCache[addr]
	if ok && slices.Contains(bes, prev) {
		return &prev
	}

	// Pick a random backend otherwise, and store it for future lookups
	idx := rand.IntN(len(bes))
	sr.affinityCache[addr] = bes[idx]
	return &bes[idx]
}
