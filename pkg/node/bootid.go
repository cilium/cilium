// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"log/slog"
	"sync"
)

var (
	localBootID string
	logOnce     sync.Once
)

func GetBootID(logger *slog.Logger) string {
	logOnce.Do(func() {
		initLocalBootID(logger)
	})
	return localBootID
}
