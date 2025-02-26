// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointmanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Cell provides the PolicyRepository and PolicyUpdater.
var Cell = cell.Module(
	"policy",
	"Contains policy rules",

	cell.Provide(newPolicyRepo),
	cell.Provide(newPolicyUpdater),
	cell.Provide(newPolicyImporter),
	cell.Config(defaultConfig),
)

type Config struct {
	EnableWellKnownIdentities bool `mapstructure:"enable-well-known-identities"`
	PolicyQueueSize           uint `mapstructure:"policy-queue-size"`
}

var defaultConfig = Config{
	// EnableWellKnownIdentities is enabled by default as this is the
	// original behavior. New default Helm templates will disable this.
	EnableWellKnownIdentities: true,
	PolicyQueueSize:           100,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-well-known-identities", def.EnableWellKnownIdentities, "Enable well-known identities for known Kubernetes components")
	flags.Uint("policy-queue-size", def.PolicyQueueSize, "Size of queue for policy-related events")
}

type policyRepoParams struct {
	cell.In

	Logger            *slog.Logger
	Lifecycle         cell.Lifecycle
	Config            Config
	CertManager       certificatemanager.CertificateManager
	IdentityManager   identitymanager.IDManager
	ClusterInfo       cmtypes.ClusterInfo
	MetricsManager    api.PolicyMetrics
	L7RulesTranslator envoypolicy.EnvoyL7RulesTranslator
}

func newPolicyRepo(params policyRepoParams) policy.PolicyRepository {
	if params.Config.EnableWellKnownIdentities {
		// Must be done before calling policy.NewPolicyRepository() below.
		num := identity.InitWellKnownIdentities(option.Config, params.ClusterInfo)
		metrics.Identity.WithLabelValues(identity.WellKnownIdentityType).Add(float64(num))
		identity.WellKnown.ForEach(func(i *identity.Identity) {
			for labelSource := range i.Labels.CollectSources() {
				metrics.IdentityLabelSources.WithLabelValues(labelSource).Inc()
			}
		})
	}

	// policy repository: maintains list of active Rules and their subject
	// security identities. Also constructs the SelectorCache, a precomputed
	// cache of label selector -> identities for policy peers.
	policyRepo := policy.NewPolicyRepository(
		params.Logger,
		identity.ListReservedIdentities(), // Load SelectorCache with reserved identities
		params.CertManager,
		params.L7RulesTranslator,
		params.IdentityManager,
		params.MetricsManager,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			policyRepo.GetSelectorCache().RegisterMetrics()
			return nil
		},
	})

	return policyRepo
}

type policyUpdaterParams struct {
	cell.In

	Logger           *slog.Logger
	PolicyRepository policy.PolicyRepository
	EndpointManager  endpointmanager.EndpointManager
}

func newPolicyUpdater(params policyUpdaterParams) *policy.Updater {
	// policyUpdater: forces policy recalculation on all endpoints.
	// Called for various events, such as named port changes
	// or certain identity updates.
	policyUpdater := policy.NewUpdater(params.Logger, params.PolicyRepository, params.EndpointManager)

	return policyUpdater
}
