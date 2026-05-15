// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"context"
	"slices"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
)

// LocalNodeWatcher populates Hubble flows local node related fields (currently
// only labels).
type LocalNodeWatcher struct {
	mu    lock.Mutex
	cache struct {
		// labels are represented as a Go map in node.LocalNode, but we need a
		// key=val slice for Hubble flows.
		labels []string
	}
}

// Run initializes the LocalNodeWatcher and subscribes to local node changes.
// It blocks until the context is cancelled.
func (w *LocalNodeWatcher) Run(ctx context.Context, localNodeStore *node.LocalNodeStore) error {
	n, err := localNodeStore.Get(ctx)
	if err != nil {
		return err
	}
	w.update(n)
	localNodeStore.Observe(ctx, w.update, w.complete)
	<-ctx.Done()
	return nil
}

// NodeLabels returns the current node labels as a sorted key=val slice.
func (w *LocalNodeWatcher) NodeLabels() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cache.labels
}

// OnDecodedFlow implements OnDecodedFlow for LocalNodeWatcher. The
// LocalNodeWatcher populates the flow's node_labels field.
func (w *LocalNodeWatcher) OnDecodedFlow(_ context.Context, flow *flowpb.Flow) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	flow.NodeLabels = w.cache.labels
	return false, nil
}

// update synchronizes the LocalNodeWatcher cache with the given LocalNode info.
func (w *LocalNodeWatcher) update(n node.LocalNode) {
	labels := sortedLabelSlice(n.Labels)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cache.labels = labels
}

// complete clears the LocalNodeWatcher cache.
func (w *LocalNodeWatcher) complete(error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cache.labels = nil
}

// sortedLabelSlice converts a given map of key/val labels, and returns a sorted
// key=val slice.
func sortedLabelSlice(src map[string]string) []string {
	labels := make([]string, 0, len(src))
	for key, val := range src {
		labels = append(labels, key+"="+val)
	}
	slices.Sort(labels)
	return labels
}
