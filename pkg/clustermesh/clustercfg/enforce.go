// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustercfg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

// RegisterEnforcer sets up the logic to write the cluster configuration to the
// kvstore, and automatically revert possible external modifications.
func RegisterEnforcer(in struct {
	cell.In

	JobGroup job.Group

	ClusterInfo   cmtypes.ClusterInfo
	ClusterConfig cmtypes.CiliumClusterConfig

	Client       kvstore.Client
	StoreFactory store.Factory
}) error {
	if !in.Client.IsEnabled() || in.ClusterInfo.ID == 0 {
		return nil
	}

	key := path.Join(kvstore.ClusterConfigPrefix, in.ClusterInfo.Name)
	value, err := json.Marshal(in.ClusterConfig)
	if err != nil {
		return fmt.Errorf("cannot marshal CiliumClusterConfig: %w", err)
	}

	watching := make(chan struct{})
	enforce := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		select {
		// Make sure that the watcher actually started. This is mostly for testing
		// purposes, to prevent possible race conditions, but it is also helpful
		// as a sanity check in production environments.
		case <-watching:
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for cluster configuration watcher to be started")
		}

		_, err := in.Client.UpdateIfDifferent(ctx, key, value, true)
		if err != nil {
			return fmt.Errorf("failed to write cluster configuration: %w", err)
		}

		return nil
	}

	trigger := job.NewTrigger()
	store := in.StoreFactory.NewWatchStore(
		in.ClusterInfo.Name, store.KVPairCreator,
		&observer{
			key:      in.ClusterInfo.Name,
			expected: value,
			trigger:  trigger,
		},
		store.RWSWithOnSyncCallback(func(context.Context) { close(watching) }),
	)

	in.JobGroup.Add(
		job.OneShot(
			"cluster-config-writer",
			func(ctx context.Context, _ cell.Health) error {
				return enforce(ctx)
			},
			job.WithRetry(3, &job.ExponentialBackoff{
				Min: 2 * time.Second,
				Max: 30 * time.Second,
			}), job.WithShutdown()),

		job.Timer(
			"cluster-config-refresh",
			enforce,
			runInterval,
			job.WithTrigger(trigger),
		),

		job.OneShot(
			"cluster-config-watcher",
			func(ctx context.Context, _ cell.Health) error {
				store.Watch(ctx, in.Client, kvstore.ClusterConfigPrefix)
				return nil
			},
		),
	)

	return nil
}

type observer struct {
	key      string
	expected []byte
	trigger  job.Trigger
}

func (o *observer) OnUpdate(key store.Key) {
	if key.GetKeyName() == o.key &&
		!bytes.Equal(key.(*store.KVPair).Value, o.expected) {
		o.trigger.Trigger()
	}
}

func (o *observer) OnDelete(key store.NamedKey) {
	if key.GetKeyName() == o.key {
		o.trigger.Trigger()
	}
}
