// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"fmt"
	"log/slog"
	"time"

	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// This is the base resync duration for synchronized Secrets.
// Jitter will be added on a per-Secret basis, so that the resyncs
// don't line up.
const resyncInterval = time.Hour

// jitterAmount represents what fraction of the resyncInterval
// resyncs will be jittered by. Default is 20 percent.
const jitterAmount = 0.2

// Cell manages K8s Secret synchronization from application namespaces
// into dedicated Cilium secrets namespace.
//
// Subsystems that are interested in having K8s Secrets synced
// (e.g. Gateway API, Ingress, ...) can register themselves via
// SecretSyncRegistrationOut.
//
// This way, multiple use-cases are sharing the same reconciler.
// This potentially prevents multiple reconcilers from interfering
// with each other.
//
// Example:
//
// cell.Provide(func registerSecretSyncRegistration(...) secretsync.SecretSyncRegistrationOut {...})
var Cell = cell.Module(
	"secret-sync",
	"Syncs TLS secrets into a dedicated secrets namespace",

	cell.Invoke(initSecretSyncReconciliation),
)

type secretSyncParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	CtrlRuntimeManager     ctrlRuntime.Manager
	Registrations          []*SecretSyncRegistration    `group:"secretSyncRegistrations"`
	ConfigMapRegistrations []*ConfigMapSyncRegistration `group:"configMapSyncRegistrations"`
}

// SecretSyncRegistrationOut can be used by other subsystems
// to register their need to have K8s Secrets synced into a
// dedicated secrets namespace.
type SecretSyncRegistrationOut struct {
	cell.Out

	SecretSyncRegistration    *SecretSyncRegistration    `group:"secretSyncRegistrations"`
	ConfigMapSyncRegistration *ConfigMapSyncRegistration `group:"configMapSyncRegistrations"`
}

func initSecretSyncReconciliation(params secretSyncParams) error {
	if params.CtrlRuntimeManager == nil {
		params.Logger.Debug("Skipping secret sync initialization due to uninitialized controller-runtime")
		return nil
	}

	params.Logger.Debug("Synchronized Secrets and Configmaps will resync", logfields.SyncInterval, resyncInterval)

	reconciler := NewSecretSyncReconciler(params.CtrlRuntimeManager.GetClient(), params.Logger, params.Registrations, resyncInterval, jitterAmount)

	if reconciler.hasRegistrations() {
		if err := reconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
			return fmt.Errorf("failed to setup secret sync reconciler: %w", err)
		}
	} else {
		params.Logger.Debug("Skipping secret sync initialization as no registrations are available")
	}

	cfgMapReconciler := NewConfigMapSyncReconciler(params.CtrlRuntimeManager.GetClient(), params.Logger, params.ConfigMapRegistrations, resyncInterval, jitterAmount)
	if !cfgMapReconciler.hasRegistrations() {
		params.Logger.Debug("Skipping configmap sync initialization as no registrations are available")
		return nil
	}

	if err := cfgMapReconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("failed to setup configmap sync reconciler: %w", err)
	}

	return nil
}
