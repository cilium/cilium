// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"iter"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
)

// injectSelectBackends overrides the load-balancing backend selection algorithm to implement
// support for the ServiceAffinity and IncludeExternal annotations.
func injectSelectBackends(cm *ClusterMesh, expCfg loadbalancer.Config, w *writer.Writer) {
	if cm == nil || !expCfg.EnableExperimentalLB {
		// ClusterMesh disabled, do not change the backend selection.
		return
	}
	w.SetSelectBackendsFunc(ClusterMeshSelectBackends{w}.SelectBackends)
}

type ClusterMeshSelectBackends struct {
	w *writer.Writer
}

func (sb ClusterMeshSelectBackends) SelectBackends(bes iter.Seq2[loadbalancer.BackendParams, statedb.Revision], svc *loadbalancer.Service, optionalFrontend *loadbalancer.Frontend) iter.Seq2[loadbalancer.BackendParams, statedb.Revision] {
	defaultBackends := sb.w.DefaultSelectBackends(bes, svc, optionalFrontend)
	affinity := annotation.GetAnnotationServiceAffinity(svc)

	useLocal := true
	localActiveBackends := 0
	useRemote := false

	switch {
	case !annotation.GetAnnotationIncludeExternal(svc):
		useRemote = false
	case affinity == annotation.ServiceAffinityNone:
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
				if be.State == loadbalancer.BackendStateActive {
					localActiveBackends++
				}
			}
		}
		switch affinity {
		case annotation.ServiceAffinityLocal:
			// Always include the local backends even if they are unhealthy and
			// only include (healthy) remote ones if there are no healthy local backends.
			useLocal = true
			useRemote = localActiveBackends == 0 && remoteBackends > 0
		case annotation.ServiceAffinityRemote:
			// Same as above but reversed.
			useRemote = true
			useLocal = remoteBackends == 0 && localBackends > 0
		}
	}

	return func(yield func(loadbalancer.BackendParams, statedb.Revision) bool) {
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
