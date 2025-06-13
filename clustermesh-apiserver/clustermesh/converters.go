// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"errors"
	"iter"
	"log/slog"
	"path"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// noneIter is a zero-length [Seq].
func noneIter[T any](func(T) bool) {}

// singleIter returns a [Seq] of length one that yields the given value.
func singleIter[T any](value T) iter.Seq[T] {
	return func(yield func(T) bool) {
		yield(value)
	}
}

// ----- CiliumNodes ----- //

func newCiliumNodeOptions() Options[*cilium_api_v2.CiliumNode] {
	return Options[*cilium_api_v2.CiliumNode]{
		Enabled:  true,
		Resource: "CiliumNode",
		Prefix:   nodeStore.NodeStorePrefix,
	}
}

// CiliumNodeConverter implements Converter[*cilium_api_v2.CiliumNode]
type CiliumNodeConverter struct{ cinfo cmtypes.ClusterInfo }

func newCiliumNodeConverter(cinfo cmtypes.ClusterInfo) Converter[*cilium_api_v2.CiliumNode] {
	return &CiliumNodeConverter{cinfo: cinfo}
}

func (nc *CiliumNodeConverter) Convert(event resource.Event[*cilium_api_v2.CiliumNode]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	if event.Kind == resource.Delete {
		node := nodeTypes.Node{Cluster: nc.cinfo.Name, Name: event.Key.Name}
		return noneIter[store.Key], singleIter[store.NamedKey](&node)
	}

	node := nodeTypes.ParseCiliumNode(event.Object)
	node.Cluster = nc.cinfo.Name
	node.ClusterID = nc.cinfo.ID
	return singleIter[store.Key](&node), noneIter[store.NamedKey]
}

// ----- CiliumIdentities ----- //

func newCiliumIdentityOptions() Options[*cilium_api_v2.CiliumIdentity] {
	return Options[*cilium_api_v2.CiliumIdentity]{
		Enabled:   true,
		Resource:  "CiliumIdentity",
		Prefix:    path.Join(identityCache.IdentitiesPath, "id"),
		StoreOpts: []store.WSSOpt{store.WSSWithSyncedKeyOverride(identityCache.IdentitiesPath)},
	}
}

// CiliumIdentityConverter implements Converter[*cilium_api_v2.CiliumIdentity]
type CiliumIdentityConverter struct{ logger *slog.Logger }

func newCiliumIdentityConverter(logger *slog.Logger) Converter[*cilium_api_v2.CiliumIdentity] {
	return &CiliumIdentityConverter{logger: logger}
}

func (ic *CiliumIdentityConverter) Convert(event resource.Event[*cilium_api_v2.CiliumIdentity]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey]) {
	if event.Kind == resource.Delete {
		key := store.NewKVPair(event.Key.Name, "")
		return noneIter[store.Key], singleIter[store.NamedKey](key)
	}

	identity := event.Object
	if len(identity.SecurityLabels) == 0 {
		ic.logger.Warn(
			"Ignoring invalid identity",
			logfields.Error, errors.New("missing security labels"),
			logfields.Identity, identity.Name,
		)

		return noneIter[store.Key], noneIter[store.NamedKey]
	}

	lbls := labels.Map2Labels(identity.SecurityLabels, "").SortedList()
	kv := store.NewKVPair(identity.Name, string(lbls))
	return singleIter[store.Key](kv), noneIter[store.NamedKey]
}
