// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
)

var (
	// ErrClusterConfigNotFound is the sentinel error returned by
	// GetClusterConfig if the cluster configuration is not found.
	ErrClusterConfigNotFound = errors.New("not found")
)

func SetClusterConfig(ctx context.Context, clusterName string, config cmtypes.CiliumClusterConfig, backend kvstore.BackendOperations) error {
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

func GetClusterConfig(ctx context.Context, clusterName string, backend kvstore.BackendOperations) (cmtypes.CiliumClusterConfig, error) {
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
