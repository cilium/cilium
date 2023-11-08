// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"fmt"

	"github.com/sirupsen/logrus"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

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

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	CtrlRuntimeManager ctrlRuntime.Manager
	Registrations      []*SecretSyncRegistration `group:"secretSyncRegistrations"`
}

// SecretSyncRegistrationOut can be used by other subsystems
// to register their need to have K8s Secrets synced into a
// dedicated secrets namespace.
type SecretSyncRegistrationOut struct {
	cell.Out

	SecretSyncRegistration *SecretSyncRegistration `group:"secretSyncRegistrations"`
}

func initSecretSyncReconciliation(params secretSyncParams) error {
	if params.CtrlRuntimeManager == nil {
		params.Logger.Debug("Skipping secret sync initialization due to uninitialized controller-runtime")
		return nil
	}

	reconciler := NewSecretSyncReconciler(params.CtrlRuntimeManager.GetClient(), params.Logger, params.Registrations)

	if !reconciler.hasRegistrations() {
		params.Logger.Debug("Skipping secret sync initialization as no registrations are available")
		return nil
	}

	if err := reconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("failed to setup secret sync reconciler: %w", err)
	}

	return nil
}
