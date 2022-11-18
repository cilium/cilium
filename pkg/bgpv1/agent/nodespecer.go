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
)

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

func NewLocalNodeStoreSpecer(params localNodeStoreSpecerParams) (nodeSpecer, error) {
	specer := &localNodeStoreSpecer{
		LocalNodeStore: params.LocalNodeStore,
		Signaler:       params.Signaler,
		Shutdowner:     params.Shutdowner,
	}
	specer.ctx, specer.cancel = context.WithCancel(context.Background())
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

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}
}

func (s *localNodeStoreSpecer) Start(ctx hive.HookContext) error {
	s.LocalNodeStore.Observe(s.ctx, func(_ types.Node) {
		s.Signaler.Event(nil)
	}, func(err error) {
		if err != nil {
			s.Shutdowner.Shutdown(hive.ShutdownWithError(err))
		}

		close(s.doneChan)
	})

	return nil
}

func (s *localNodeStoreSpecer) Stop(ctx hive.HookContext) error {
	s.cancel()

	select {
	case <-s.doneChan:
	case <-s.ctx.Done():
	}

	return nil
}

func (s *localNodeStoreSpecer) Annotations() (map[string]string, error) {
	n := s.LocalNodeStore.Get()
	return n.Annotations, nil
}

func (s *localNodeStoreSpecer) Labels() (map[string]string, error) {
	n := s.LocalNodeStore.Get()
	return n.Labels, nil
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
