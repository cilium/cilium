// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"context"
	"slices"

	"github.com/cilium/stream"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
)

// LocalNodeWatcher populate Hubble flows local node related fields (currently
// only labels).
type LocalNodeWatcher struct {
	mu      lock.Mutex
	updated int // update counter
	cache   struct {
		// labels are represented as a Go map in node.LocalNode, but we need a
		// key=val slice for Hubble flows.
		labels []string
	}
}

// NewLocalNodeWatcher return a new LocalNodeWatcher. The given context control
// whether the LocalNodeWatcher gets updated by the localNodeStream. It is safe
// to use the returned LocalNodeWatcher once the context is cancelled, but its
// information might be out-of-date.
func NewLocalNodeWatcher(ctx context.Context, localNodeStream stream.Observable[node.LocalNode]) *LocalNodeWatcher {
	watcher := LocalNodeWatcher{}
	localNodeStream.Observe(ctx, watcher.update, watcher.complete)
	return &watcher
}

// OnDecodedFlow implements OnDecodedFlow for LocalNodeWatcher. The
// LocalNodeWatcher populate the flow's node_labels field.
func (w *LocalNodeWatcher) OnDecodedFlow(_ context.Context, flow *flowpb.Flow) (bool, error) {
	w.mu.Lock()
	flow.NodeLabels = w.cache.labels
	w.mu.Unlock()
	return false, nil
}

// update synchronize the LocalNodeWatcher cache with the given LocalNode info.
func (w *LocalNodeWatcher) update(n node.LocalNode) {
	labels := sortedLabelSlice(n.Labels)
	w.mu.Lock()
	w.cache.labels = labels
	w.updated++
	w.mu.Unlock()
}

// generation return this watcher update counter.
func (w *LocalNodeWatcher) generation() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.updated
}

// complete clears the LocalNodeWatcher cache.
func (w *LocalNodeWatcher) complete(error) {
	w.mu.Lock()
	w.cache.labels = nil
	w.updated++
	w.mu.Unlock()
}

// sortedLabelSlice convert a given map of key/val labels, and return a sorted
// key=val slice.
func sortedLabelSlice(src map[string]string) []string {
	labels := make([]string, 0, len(src))
	for key, val := range src {
		labels = append(labels, key+"="+val)
	}
	slices.Sort(labels)
	return labels
}
