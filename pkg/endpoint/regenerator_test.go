// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRegeneratorWaitForIPCacheSync(t *testing.T) {
	regenerator := Regenerator{
		logger: func() logrus.FieldLogger {
			logger := logrus.New()
			logger.SetLevel(logrus.FatalLevel)
			return logger
		}(),

		cmWaitFn: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},

		RegeneratorConfig: RegeneratorConfig{
			ClusterMeshIPIdentitiesSyncTimeout: 10 * time.Millisecond,
		},
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
