// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"encoding/json"
	"path"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
)

func SetClusterConfig(ctx context.Context, clusterName string, config *cmtypes.CiliumClusterConfig, backend kvstore.BackendOperations) error {
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

func GetClusterConfig(ctx context.Context, clusterName string, backend kvstore.BackendOperations) (*cmtypes.CiliumClusterConfig, error) {
	var config cmtypes.CiliumClusterConfig

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, path.Join(kvstore.ClusterConfigPrefix, clusterName))
	if err != nil {
		return nil, err
	}

	// Cluster configuration missing, but it's not an error
	if val == nil {
		return nil, nil
	}

	if err := json.Unmarshal(val, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// IsClusterConfigRequired returns whether the remote kvstore guarantees that the
// cilium cluster config will be eventually created.
func IsClusterConfigRequired(ctx context.Context, backend kvstore.BackendOperations) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, kvstore.HasClusterConfigPath)
	return val != nil, err
}
