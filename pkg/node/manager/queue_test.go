// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQPush(t *testing.T) {
	uu := map[string]struct {
		items, e []string
	}{
		"empty": {},
		"happy": {
			items: []string{"a", "b", "c"},
			e:     []string{"a", "b", "c"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			var q queue[string]

			for i := range u.items {
				q.push(&u.items[i])
			}
			for i := 0; i < len(u.items); i++ {
				v := q.pop()
				assert.Less(t, i, len(u.e))
				assert.Equal(t, u.e[i], *v)
			}
			assert.True(t, q.isEmpty())
		})
	}
}

func TestQPop(t *testing.T) {
	uu := map[string]struct {
		items, e []string
	}{
		"empty": {},
		"happy": {
			items: []string{"a", "b", "c"},
			e:     []string{"a", "b", "c"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			var q queue[string]

			for i := range u.items {
				q.push(&u.items[i])
			}
			for q.pop() != nil {
			}
			assert.True(t, q.isEmpty())
		})
	}
}
