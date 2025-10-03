// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/policy/cookie"
)

func TestBakedCookieIsEmpty(t *testing.T) {
	uu := map[string]struct {
		cookie *cookie.BakedCookie
		e      bool
	}{
		"null": {
			e: true,
		},

		"empty": {
			cookie: cookie.NewBakedCookie("", nil, 0),
			e:      true,
		},

		"with-labels": {
			cookie: cookie.NewBakedCookie("[k8s:a=b]", nil, 0),
		},

		"with-log": {
			cookie: cookie.NewBakedCookie("", []string{"blee"}, 0),
		},

		"full-monty": {
			cookie: cookie.NewBakedCookie("[k8s:a=b]", []string{"blee"}, 0),
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.cookie.IsEmpty())
		})
	}
}
