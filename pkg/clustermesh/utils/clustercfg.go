// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// ErrClusterConfigNotFound is the sentinel error returned by
	// GetClusterConfig if the cluster configuration is not found.
	ErrClusterConfigNotFound = errors.New("not found")

	// clusterConfigEnforcerGroup is the group for the controllers enforcing
	clusterConfigEnforcerGroup = controller.NewGroup("clustermesh-cluster-config-enforcer")

	// runInterval is the cluster configuration enforcement interval
	runInterval = 5 * time.Minute
)

type ClusterConfigBackend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error)
}

func SetClusterConfig(ctx context.Context, clusterName string, config cmtypes.CiliumClusterConfig, backend ClusterConfigBackend) error {
	key := path.Join(kvstore.ClusterConfigPrefix, clusterName)

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

// EnforceClusterConfig synchronously writes the cluster configuration, and
// additionally registers a background task to periodically enforce its presence
// (e.g., in case the associated lease unexpectedly expired).
func EnforceClusterConfig(
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
			Group:       clusterConfigEnforcerGroup,
			RunInterval: runInterval,
			DoFunc: func(ctx context.Context) error {
				err := SetClusterConfig(ctx, clusterName, config, backend)
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

func GetClusterConfig(ctx context.Context, clusterName string, backend ClusterConfigBackend) (cmtypes.CiliumClusterConfig, error) {
	var config cmtypes.CiliumClusterConfig

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, path.Join(kvstore.ClusterConfigPrefix, clusterName))
	if err != nil {
		return cmtypes.CiliumClusterConfig{}, err
	}

	if val == nil {
		return cmtypes.CiliumClusterConfig{}, ErrClusterConfigNotFound
	}

	if err := json.Unmarshal(val, &config); err != nil {
		return cmtypes.CiliumClusterConfig{}, err
	}

	return config, nil
}
