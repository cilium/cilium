// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"
)

// checkpoint writes the state of the local allocators to disk. This is used for restoration,
// to ensure that numeric identities are, as much as possible, stable across agent restarts.
//
// Do not call this directly, rather, use m.checkpointTrigger.Trigger()
func (m *CachingIdentityAllocator) checkpoint(ctx context.Context) error {
	if m.checkpointPath == "" {
		return nil // this is a unit test
	}
	scopedLog := m.logger.With(logfields.Path, m.checkpointPath)

	ids := make([]*identity.Identity, 0, m.localIdentities.size()+m.localNodeIdentities.size())
	ids = m.localIdentities.checkpoint(ids)
	ids = m.localNodeIdentities.checkpoint(ids)

	// use renameio to prevent partial writes
	out, err := renameio.NewPendingFile(m.checkpointPath, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
	if err != nil {
		scopedLog.Error("failed to prepare checkpoint file", logfields.Error, err)
		return err
	}
	defer out.Cleanup()

	jw := jsoniter.ConfigFastest.NewEncoder(out)
	if err := jw.Encode(ids); err != nil {
		scopedLog.Error("failed to marshal identity checkpoint state", logfields.Error, err)
		return err
	}
	if err := out.CloseAtomicallyReplace(); err != nil {
		scopedLog.Error("failed to write identity checkpoint file", logfields.Error, err)
		return err
	}
	scopedLog.Debug("Wrote local identity allocator checkpoint")
	return nil
}

// EnableCheckpointing enables checkpointing the local allocator state.
// The CachingIdentityAllocator is used in multiple places, but we only want to
// checkpoint the "primary" allocator
func (m *CachingIdentityAllocator) EnableCheckpointing() {
	controllerManager := controller.NewManager()
	controllerGroup := controller.NewGroup("identity-allocator")
	controllerName := "local-identity-checkpoint"
	triggerDone := make(chan struct{})
	t, _ := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 10 * time.Second,
		TriggerFunc: func(reasons []string) {
			controllerManager.UpdateController(controllerName, controller.ControllerParams{
				Group:    controllerGroup,
				DoFunc:   m.checkpoint,
				StopFunc: m.checkpoint, // perform one last checkpoint when the controller is removed
			})
		},
		ShutdownFunc: func() {
			controllerManager.RemoveControllerAndWait(controllerName) // waits for StopFunc
			close(triggerDone)
		},
	})

	m.checkpointTrigger = t
	m.triggerDone = triggerDone
}
