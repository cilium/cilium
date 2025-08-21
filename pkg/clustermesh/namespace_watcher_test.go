// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespaceWatcherBasic(t *testing.T) {
	// Test basic configuration functionality
	config := NamespaceWatcherConfig{
		DefaultGlobalNamespace: false,
	}

	watcher := NewNamespaceWatcher(slog.Default(), config)

	// Test initial state (no filtering active)
	assert.False(t, watcher.IsFilteringActive())

	// In backwards compatibility mode, all namespaces are considered global
	assert.True(t, watcher.IsGlobalNamespace("any-namespace"))

	// Test that a namespace without annotation is global in backwards compatibility mode
	assert.True(t, watcher.IsGlobalNamespace("test-namespace"))
}
