// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/logging"
)

func TestRegeneratorWaitForIPCacheSync(t *testing.T) {
	regenerator := Regenerator{
		logger: func() logging.FieldLogger {
			return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logging.LevelPanic}))
		}(),

		cmWaitFn: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},

		cmWaitTimeout: 10 * time.Millisecond,
	}

	tests := []struct {
		name   string
		ctx    context.Context
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "valid context",
			ctx:    context.Background(),
			assert: assert.NoError,
		},
		{
			name: "expired context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}(),
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, regenerator.WaitForClusterMeshIPIdentitiesSync(tt.ctx))
		})
	}
}
