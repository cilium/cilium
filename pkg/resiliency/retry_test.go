// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/resiliency"
)

func TestIsRetryable(t *testing.T) {
	uu := map[string]struct {
		e error
		b bool
	}{
		"none": {},
		"plain": {
			e: errors.New("blee"),
		},
		"res_ext": {
			e: resiliency.NewRetryableErr(errors.New("external")),
			b: true,
		},
		"multi-plain": {
			e: errors.Join(
				errors.New("blee"),
				errors.New("fred"),
			),
		},
		"multi-retryable": {
			e: errors.Join(
				resiliency.NewRetryableErr(errors.New("dp")),
				errors.New("fred"),
			),
			b: true,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.b, resiliency.IsRetryable(u.e))
		})
	}
}
