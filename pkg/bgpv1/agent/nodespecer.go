// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/workerpool"
)

// nodeSpecer is an abstraction which allows us to mock/fake out the local node resource during testing.
type nodeSpecer interface {
	Annotations() (map[string]string, error)
	Labels() (map[string]string, error)
	PodCIDRs() ([]string, error)
}

type localNodeStoreSpecerParams struct {
	cell.In

	Lifecycle      hive.Lifecycle
	Config         *option.DaemonConfig
	LocalNodeStore node.LocalNodeStore
	Signaler       Signaler
	Shutdowner     hive.Shutdowner
}

// NewLocalNodeStoreSpecer constructs a new nodeSpecer and registers it in the hive lifecycle
func NewLocalNodeStoreSpecer(params localNodeStoreSpecerParams) (nodeSpecer, error) {
	specer := &localNodeStoreSpecer{
		LocalNodeStore: params.LocalNodeStore,
		Signaler:       params.Signaler,
		Shutdowner:     params.Shutdowner,
		workerpool:     workerpool.New(1),
	}
	params.Lifecycle.Append(specer)
	return specer, nil
}

// localNodeStoreSpecer abstracts the underlying mechanism to list information about the
// Node resource Cilium is running on.
//
// The localNodeStoreSpecer observes changes to the local node info and signals the Signaler
// when it changes.
type localNodeStoreSpecer struct {
	LocalNodeStore node.LocalNodeStore
	Signaler       Signaler
	Shutdowner     hive.Shutdowner

	workerpool *workerpool.WorkerPool
}

func (s *localNodeStoreSpecer) Start(_ hive.HookContext) error {
	s.workerpool.Submit("local-node-store-run", s.run)

	return nil
}

func (s *localNodeStoreSpecer) Stop(ctx hive.HookContext) error {
	doneChan := make(chan struct{})

	go func() {
		s.workerpool.Close()
		close(doneChan)
	}()

	select {
	case <-doneChan:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// run observes the local node store for changes and triggers the signaller when the local node has been updated.
func (s *localNodeStoreSpecer) run(ctx context.Context) error {
	doneChan := make(chan struct{})

	next := func(_ types.Node) {
		s.Signaler.Event(nil)
	}

	complete := func(err error) {
		if err != nil {
			s.Shutdowner.Shutdown(hive.ShutdownWithError(err))
		}

		close(doneChan)
	}

	s.LocalNodeStore.Observe(ctx, next, complete)

	<-doneChan
	return nil
}

func (s *localNodeStoreSpecer) Annotations() (map[string]string, error) {
	return s.LocalNodeStore.Get().Annotations, nil
}

func (s *localNodeStoreSpecer) Labels() (map[string]string, error) {
	return s.LocalNodeStore.Get().Labels, nil
}

func (s *localNodeStoreSpecer) PodCIDRs() ([]string, error) {
	n := s.LocalNodeStore.Get()

	var podCIDRs []string
	if n.IPv4AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv4AllocCIDR.String())
		for _, secCidr := range n.IPv4SecondaryAllocCIDRs {
			podCIDRs = append(podCIDRs, secCidr.String())
		}
	}

	if n.IPv6AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv6AllocCIDR.String())
		for _, secCidr := range n.IPv6SecondaryAllocCIDRs {
			podCIDRs = append(podCIDRs, secCidr.String())
		}
	}

	return podCIDRs, nil
}
