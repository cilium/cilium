// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustercfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// ErrNotFound is the sentinel error returned by [clustercfg.Get] if the
	// cluster configuration is not found.
	ErrNotFound = errors.New("not found")

	// enforcerGroup is the group for the controllers enforcing
	enforcerGroup = controller.NewGroup("clustermesh-cluster-config-enforcer")

	// runInterval is the cluster configuration enforcement interval
	runInterval = 5 * time.Minute
)

type ClusterConfigBackend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error)
	ListAndWatch(ctx context.Context, prefix string, opts ...kvstore.ListAndWatchOption) kvstore.EventChan
}

func Set(ctx context.Context, clusterName string, config cmtypes.CiliumClusterConfig, backend ClusterConfigBackend) error {
	key := kvstore.JoinKey(kvstore.ClusterConfigPrefix, clusterName)

	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	_, err = backend.UpdateIfDifferent(ctx, key, val, true)
	if err != nil {
		return err
	}

	return nil
}

// Enforce synchronously writes the cluster configuration, and additionally
// registers a background task to periodically enforce its presence
// (e.g., in case the associated lease unexpectedly expired).
func Enforce(
	ctx context.Context, clusterName string, config cmtypes.CiliumClusterConfig,
	backend ClusterConfigBackend, log *slog.Logger,
) (stopAndWait func(), err error) {
	var (
		mgr = controller.NewManager()
		ch  = make(chan error, 1)
	)

	mgr.UpdateController(
		fmt.Sprintf("clustermesh-cluster-config-enforcer-%s", clusterName),
		controller.ControllerParams{
			Context:     ctx,
			Group:       enforcerGroup,
			RunInterval: runInterval,
			DoFunc: func(ctx context.Context) error {
				err := Set(ctx, clusterName, config, backend)
				select {
				case ch <- err:
					if err != nil {
						return controller.NewExitReason("initial enforcement failed")
					}
					return nil

				default:
					if err != nil {
						log.Warn("Failed to write cluster configuration", logfields.Error, err)
					}

					return err
				}
			},
		},
	)

	// Wait to the initial synchronous enforcement, and then return.
	err = <-ch
	ch = nil

	return mgr.RemoveAllAndWait, err
}

func Get(ctx context.Context, clusterName string, backend ClusterConfigBackend) (cmtypes.CiliumClusterConfig, error) {
	var config cmtypes.CiliumClusterConfig

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, kvstore.JoinKey(kvstore.ClusterConfigPrefix, clusterName))
	if err != nil {
		return cmtypes.CiliumClusterConfig{}, err
	}

	if val == nil {
		return cmtypes.CiliumClusterConfig{}, ErrNotFound
	}

	if err := json.Unmarshal(val, &config); err != nil {
		return cmtypes.CiliumClusterConfig{}, err
	}

	return config, nil
}

// Watch watches the configuration of the given cluster and sends the observed
// configurations to the configUpdates channel. This function already
// de-deduplicate identical configurations, and ignores any deletion event.
func Watch(
	ctx context.Context, clusterName string,
	backend ClusterConfigBackend, log *slog.Logger,
	configUpdates chan<- cmtypes.CiliumClusterConfig,
) {
	key := kvstore.JoinKey(kvstore.ClusterConfigPrefix, clusterName)

	var current *cmtypes.CiliumClusterConfig
	for event := range backend.ListAndWatch(ctx, key, kvstore.WithExactKey()) {
		// Ignore deletion events on purpose to not propagate a temporary
		// deletion which may be associated to a lease expiration. The list
		// done event does not carry a configuration so it's similarly ignored.
		if event.Typ == kvstore.EventTypeDelete || event.Typ == kvstore.EventTypeListDone {
			continue
		}

		var config cmtypes.CiliumClusterConfig
		if err := json.Unmarshal(event.Value, &config); err != nil {
			log.Warn("Failed to unmarshal cluster configuration",
				logfields.Error, err,
				logfields.ClusterName, clusterName)
			continue
		}

		if current != nil && current.DeepEqual(&config) {
			continue
		}

		select {
		case configUpdates <- config:
			current = &config
		case <-ctx.Done():
			return
		}
	}
}
