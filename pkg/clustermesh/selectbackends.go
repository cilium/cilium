// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"iter"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/source"
)

// injectSelectBackends overrides the load-balancing backend selection algorithm to implement
// support for the ServiceAffinity and IncludeExternal annotations.
func injectSelectBackends(cfg common.Config, expCfg experimental.Config, w *experimental.Writer) {
	if cfg.ClusterMeshConfig == "" || !expCfg.EnableExperimentalLB {
		// ClusterMesh disabled, do not change the backend selection.
		return
	}
	w.SetSelectBackendsFunc(ClusterMeshSelectBackends{w}.SelectBackends)
}

type ClusterMeshSelectBackends struct {
	w *experimental.Writer
}

func (sb ClusterMeshSelectBackends) SelectBackends(bes iter.Seq2[experimental.BackendParams, statedb.Revision], svc *experimental.Service, optionalFrontend *experimental.Frontend) iter.Seq2[experimental.BackendParams, statedb.Revision] {
	defaultBackends := sb.w.DefaultSelectBackends(bes, svc, optionalFrontend)
	affinity := svc.GetServiceAffinityAnnotation()

	useLocal := true
	useRemote := false

	switch {
	case !svc.GetIncludeExternalAnnotation():
		useRemote = false
	case affinity == experimental.ServiceAffinityNone:
		useRemote = true
	default:
		// Counts of healthy local and remote backends.
		localBackends, remoteBackends := 0, 0
		for be := range defaultBackends {
			// Don't count unhealthy backends. We include terminating backends in the count as
			// we don't want those removed.
			healthy := be.State == loadbalancer.BackendStateActive || be.State == loadbalancer.BackendStateTerminating
			healthy = healthy && !be.Unhealthy
			if !healthy {
				continue
			}
			if be.Source == source.ClusterMesh {
				remoteBackends++
			} else {
				localBackends++
			}
		}
		switch affinity {
		case experimental.ServiceAffinityLocal:
			// Always include the local backends even if they are unhealthy and
			// only include (healthy) remote ones if there are no healthy local backends.
			useLocal = true
			useRemote = localBackends == 0 && remoteBackends > 0
		case experimental.ServiceAffinityRemote:
			// Same as above but reversed.
			useRemote = true
			useLocal = remoteBackends == 0 && localBackends > 0
		}
	}

	return func(yield func(experimental.BackendParams, statedb.Revision) bool) {
		for be, rev := range defaultBackends {
			if be.Source == source.ClusterMesh {
				if !useRemote {
					continue
				}
			} else if !useLocal {
				continue
			}

			if !yield(be, rev) {
				break
			}
		}
	}
}
