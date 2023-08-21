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
			e: resiliency.WrapResExt(errors.New("blee")),
			b: true,
		},
		"res_limit": {
			e: resiliency.WrapResLimit(errors.New("blee")),
		},
		"multi-plain": {
			e: errors.Join(
				errors.New("blee"),
				errors.New("fred"),
			),
		},
		"multi-res-ext": {
			e: errors.Join(
				resiliency.WrapResExt(errors.New("blee")),
				errors.New("fred"),
			),
			b: true,
		},
		"multi-res-limit": {
			e: errors.Join(
				resiliency.WrapResLimit(errors.New("blee")),
				errors.New("fred"),
			),
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.b, resiliency.IsRetryable(u.e))
		})
	}
}
