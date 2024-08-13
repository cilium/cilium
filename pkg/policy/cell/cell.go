// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// Cell provides the PolicyRepository and PolicyUpdater.
var Cell = cell.Module(
	"policy",
	"Contains policy rules",

	cell.Provide(newPolicyRepo),
	cell.Provide(newPolicyUpdater),
)

type policyRepoParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	CertManager     certificatemanager.CertificateManager
	SecretManager   certificatemanager.SecretManager
	IdentityManager *identitymanager.IdentityManager
	ClusterInfo     cmtypes.ClusterInfo
}

func newPolicyRepo(params policyRepoParams) *policy.Repository {
	if option.Config.EnableWellKnownIdentities {
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
	policyRepo := policy.NewStoppedPolicyRepository(
		identity.ListReservedIdentities(), // Load SelectorCache with reserved identities
		params.CertManager,
		params.SecretManager,
		params.IdentityManager,
	)
	policyRepo.SetEnvoyRulesFunc(envoy.GetEnvoyHTTPRules)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			policyRepo.Start()
			return nil
		},
	})

	return policyRepo
}

type policyUpdaterParams struct {
	cell.In

	Lifecycle        cell.Lifecycle
	PolicyRepository *policy.Repository
	EndpointManager  endpointmanager.EndpointManager
}

func newPolicyUpdater(params policyUpdaterParams) *policy.Updater {
	// policyUpdater: forces policy recalculation on all endpoints.
	// Called for various events, such as named port changes
	// or certain identity updates.
	policyUpdater := policy.NewUpdater(params.PolicyRepository, params.EndpointManager)

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			policyUpdater.Shutdown()
			return nil
		},
	})

	return policyUpdater
}
