// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"iter"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/clustermesh/common"
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

func (sb ClusterMeshSelectBackends) SelectBackends(txn statedb.ReadTxn, tbl statedb.Table[*experimental.Backend], fe *experimental.Frontend) iter.Seq2[experimental.BackendParams, statedb.Revision] {
	svc := fe.Service()
	includeExternal := svc.GetIncludeExternalAnnotation()
	defaultBackends := sb.w.DefaultSelectBackends(txn, tbl, fe)

	getCounts := func() (int, int) {
		countLocal, countRemote := 0, 0
		for be := range defaultBackends {
			if be.Source == source.ClusterMesh {
				countRemote++
			} else {
				countLocal++
			}
		}
		return countLocal, countRemote
	}

	// Figure out whether to use local cluster backends or remote, or both.
	var useRemote bool

	if !includeExternal {
		useRemote = false
	} else {
		switch svc.GetServiceAffinityAnnotation() {
		case experimental.ServiceAffinityNone:
			useRemote = true
		case experimental.ServiceAffinityLocal:
			countLocal, _ := getCounts()
			useRemote = countLocal == 0
		case experimental.ServiceAffinityRemote:
			countLocal, countRemote := getCounts()
			useRemote = countRemote > 0 || countLocal == 0
		}
	}

	return func(yield func(experimental.BackendParams, statedb.Revision) bool) {
		for be, rev := range defaultBackends {
			if be.Source == source.ClusterMesh && !useRemote {
				continue
			}
			if !yield(be, rev) {
				break
			}
		}
	}
}
