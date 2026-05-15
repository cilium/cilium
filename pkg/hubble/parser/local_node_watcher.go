// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"context"
	"slices"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
)

// LocalNodeWatcher populates Hubble flows local node related fields such as
// the node name and labels.
type LocalNodeWatcher struct {
	mu    lock.Mutex
	cache struct {
		// nodeName is the absolute node name (cluster/node or just node).
		nodeName string
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

// NodeInfo returns the current node name and labels under a single lock.
func (w *LocalNodeWatcher) NodeInfo() (string, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cache.nodeName, w.cache.labels
}

// NodeName returns the current absolute node name.
func (w *LocalNodeWatcher) NodeName() string {
	name, _ := w.NodeInfo()
	return name
}

// NodeLabels returns the current node labels as a sorted key=val slice.
func (w *LocalNodeWatcher) NodeLabels() []string {
	_, labels := w.NodeInfo()
	return labels
}

// update synchronizes the LocalNodeWatcher cache with the given LocalNode info.
func (w *LocalNodeWatcher) update(n node.LocalNode) {
	nodeName := n.Fullname()
	labels := sortedLabelSlice(n.Labels)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cache.nodeName = nodeName
	w.cache.labels = labels
}

// complete clears the LocalNodeWatcher cache.
func (w *LocalNodeWatcher) complete(error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cache.nodeName = ""
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
