// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/iptables"
)

// ztunnelStateFile is a marker file written to StateDir when ztunnel is
// enabled. Its presence on a subsequent agent start with enable-ztunnel=false
// triggers cleanup of in-pod redirect rules left in previously-enrolled pods.
const ztunnelStateFile = "ztunnel_enabled"

// Cell provides cleanup of ztunnel in-pod rules when ztunnel is disabled.
var Cell = cell.Module(
	"cleanup",
	"Cleanup of ztunnel in-pod rules",
	cell.ProvidePrivate(newCleanupConfig),
	cell.Invoke(registerCleanup),
)

type cleanupConfig struct {
	stateDir   string
	enableIPv4 bool
	enableIPv6 bool
}

func newCleanupConfig(dcfg *option.DaemonConfig) cleanupConfig {
	return cleanupConfig{
		stateDir:   dcfg.StateDir,
		enableIPv4: dcfg.EnableIPv4,
		enableIPv6: dcfg.EnableIPv6,
	}
}

type cleanupParams struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Logger          *slog.Logger
	JobGroup        job.Group
	Config          config.Config
	CleanupConfig   cleanupConfig
	EndpointManager endpointmanager.EndpointManager
	RestorerPromise promise.Promise[endpointstate.Restorer]
}

// registerCleanup handles two cases:
//
//  1. ztunnel enabled: write a marker file so a future disable knows cleanup
//     is needed.
//  2. ztunnel disabled + marker present: register a one-shot job that removes
//     in-pod redirect rules from all restored endpoints, then removes the
//     marker.
func registerCleanup(p cleanupParams) error {
	markerPath := filepath.Join(p.CleanupConfig.stateDir, ztunnelStateFile)

	if p.Config.EnableZTunnel {
		// Persist a marker so that a subsequent run with enable-ztunnel=false
		// knows that cleanup is required.
		p.Lifecycle.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return os.WriteFile(markerPath, nil, 0600)
			},
		})
		return nil
	}

	// ztunnel is disabled. Only run cleanup if a previous agent run had it
	// enabled (marker file exists).
	if _, err := os.Stat(markerPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat ztunnel state marker %q: %w", markerPath, err)
	}

	p.JobGroup.Add(job.OneShot("ztunnel-inpod-cleanup", func(ctx context.Context, _ cell.Health) error {
		return runCleanup(ctx, p.Logger, p.RestorerPromise, p.EndpointManager, p.CleanupConfig)
	}))
	return nil
}

func runCleanup(ctx context.Context, logger *slog.Logger, restorerPromise promise.Promise[endpointstate.Restorer], epMgr endpointmanager.EndpointManager, cfg cleanupConfig) error {
	restorer, err := restorerPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("await endpoint restorer: %w", err)
	}
	if err := restorer.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return fmt.Errorf("wait for endpoint restore: %w", err)
	}

	logger.Info("Starting ztunnel in-pod rules cleanup")

	var cleanupErr error
	var cleaned int
	for _, ep := range epMgr.GetEndpoints() {
		netnsPath := ep.GetContainerNetnsPath()
		if netnsPath == "" {
			continue
		}

		ns, err := netns.OpenPinned(netnsPath)
		if err != nil {
			// Pod netns no longer exists (container exited); rules are
			// already gone with it.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			logger.Warn("Failed to open pod netns for ztunnel cleanup",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}

		if err := ns.Do(func() error {
			return iptables.DeleteInPodRules(logger, cfg.enableIPv4, cfg.enableIPv6)
		}); err != nil {
			ns.Close()
			logger.Warn("Failed to delete ztunnel in-pod rules",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		ns.Close()
		cleaned++
	}

	logger.Info("Finished ztunnel in-pod rules cleanup",
		"cleaned", cleaned,
	)

	if cleanupErr != nil {
		// Keep the marker so the next restart retries.
		return cleanupErr
	}

	// All endpoints cleaned successfully; remove the marker.
	markerPath := filepath.Join(cfg.stateDir, ztunnelStateFile)
	if err := os.Remove(markerPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove ztunnel state marker",
			logfields.Path, markerPath,
			logfields.Error, err,
		)
	}
	return nil
}
