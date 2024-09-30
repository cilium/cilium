// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package directory

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
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
	cell.Provide(newDirectoryPolicyResourcesWatcher,
		func() DirectoryWatcherReadStatus {
			return make(DirectoryWatcherReadStatus)
		}),
)

type PolicyManager interface {
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

type DirectoryWatcherReadStatus chan struct{}

type PolicyWatcherParams struct {
	cell.In

	ReadStatus DirectoryWatcherReadStatus
	Lifecycle  cell.Lifecycle
	Logger     logrus.FieldLogger
}

type ResourcesWatcher interface {
	WatchDirectoryPolicyResources(ctx context.Context, policyManager PolicyManager)
}

type PolicyResourcesWatcher struct {
	params PolicyWatcherParams
	cfg    Config
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

func newDirectoryPolicyResourcesWatcher(p PolicyWatcherParams, cfg Config) ResourcesWatcher {
	if cfg.StaticCNPPath == "" {
		close(p.ReadStatus)
		return nil
	}

	return &PolicyResourcesWatcher{
		params: p,
		cfg:    cfg,
	}
}

// WatchDirectoryPolicyResources starts watching Cilium Network policy files created under a directory.
func (p *PolicyResourcesWatcher) WatchDirectoryPolicyResources(ctx context.Context, policyManager PolicyManager) {
	w := newPolicyWatcher(ctx, policyManager, p)
	w.watchDirectory(ctx)
}

// newPolicyWatcher constructs a new policy watcher.
// This constructor unfortunately cannot be started via the Hive lifecycle as
// there exists a circular dependency between this watcher and the Daemon:
// The constructor newDaemon cannot complete before all pre-existing
// Cilium Network Policy defined as yaml under specific directory have been added via the PolicyManager
// (i.e. watchDirectory has observed the CNP file addition).
// Because the PolicyManager interface itself is implemented by the Daemon
// struct, we have a circular dependency.
func newPolicyWatcher(ctx context.Context, policyManager PolicyManager, p *PolicyResourcesWatcher) *policyWatcher {
	w := &policyWatcher{
		log:                p.params.Logger,
		policyManager:      policyManager,
		readStatus:         p.params.ReadStatus,
		config:             p.cfg,
		fileNameToCnpCache: make(map[string]*cilium_v2.CiliumNetworkPolicy),
	}
	return w
}
