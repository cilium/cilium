// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package directory

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

// Cell provides the Directory policy watcher. The Directory policy watcher watches
// CiliumNetworkPolicy, CiliumClusterWideNetworkPolicy created/deleted under a directory
// specified through cilium config. It reads and translates them to Cilium's own
// policy representation (api.Rules) and updates the policy repository
// (via PolicyManager) accordingly.
var Cell = cell.Module(
	"policy-directory-watcher",
	"Watches Directory for cilium network policy file updates",
	cell.Config(defaultConfig),
	cell.Provide(providePolicyWatcher),
)

type DirectoryWatcherReadStatus interface {
	Wait()
}
type PolicyWatcherParams struct {
	cell.In

	Lifecycle               cell.Lifecycle
	Logger                  *slog.Logger
	Importer                policycell.PolicyImporter
	ClusterInfo             cmtypes.ClusterInfo
	ClusterMeshPolicyConfig cmtypes.PolicyConfig
}

type Config struct {
	StaticCNPPath string
}

const (
	// StaticCNPPath defines the directory path for static cilium network policy yaml files.
	staticCNPPath = "static-cnp-path"
)

var defaultConfig = Config{
	StaticCNPPath: "", // Disabled
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.String(staticCNPPath, defaultConfig.StaticCNPPath, "Directory path to watch and load static cilium network policy yaml files.")
}

func providePolicyWatcher(p PolicyWatcherParams, cfg Config) DirectoryWatcherReadStatus {
	if cfg.StaticCNPPath == "" {
		return &sync.WaitGroup{}
	}
	pw := newPolicyWatcher(p, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			pw.watchDirectory(ctx)
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return pw
}

// newPolicyWatcher constructs a new policy watcher.
func newPolicyWatcher(p PolicyWatcherParams, cfg Config) *policyWatcher {
	w := &policyWatcher{
		log:                p.Logger,
		policyImporter:     p.Importer,
		config:             cfg,
		clusterName:        cmtypes.LocalClusterNameForPolicies(p.ClusterMeshPolicyConfig, p.ClusterInfo.Name),
		fileNameToCnpCache: make(map[string]*cilium_v2.CiliumNetworkPolicy),
	}
	w.synced.Add(1)
	return w
}
