// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/resiliency"
)

func TestRetries(t *testing.T) {
	var maxRetries int

	uu := map[string]struct {
		d   time.Duration
		m   int
		f   resiliency.RetryFunc
		err error
		e   int
	}{
		"no-retries": {
			d: 10 * time.Millisecond,
			m: 3,
			f: func(ctx context.Context, retries int) (bool, error) {
				maxRetries = retries
				return true, nil
			},
			e: 1,
		},
		"happy": {
			d: 10 * time.Millisecond,
			m: 3,
			f: func(ctx context.Context, retries int) (bool, error) {
				maxRetries = retries
				if retries < 3 {
					return false, nil
				}
				return true, nil
			},
			e: 3,
		},
		"error-complete": {
			d: 10 * time.Millisecond,
			m: 3,
			f: func(ctx context.Context, retries int) (bool, error) {
				maxRetries = retries
				return true, errors.New("boom")
			},
			err: errors.New("boom"),
			e:   1,
		},
		"error-retry": {
			d: 10 * time.Millisecond,
			m: 3,
			f: func(ctx context.Context, retries int) (bool, error) {
				maxRetries = retries
				return false, errors.New("boom")
			},
			err: errors.New("boom"),
			e:   1,
		},
	}

	for k := range uu {
		u := uu[k]
		maxRetries = 0
		t.Run(k, func(t *testing.T) {
			err := resiliency.Retry(context.Background(), u.d, u.m, u.f)
			if err != nil {
				assert.Equal(t, u.err, err)
			}
			assert.Equal(t, u.e, maxRetries)
		})
	}
}
