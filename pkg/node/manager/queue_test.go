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
			for i := range u.items {
				v, ok := q.pop()
				assert.True(t, ok)
				assert.Less(t, i, len(u.e))
				assert.Equal(t, u.e[i], *v)
			}
			assert.True(t, q.isEmpty())

			v, ok := q.pop()
			assert.False(t, ok)
			assert.Nil(t, v)
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
			for {
				if _, ok := q.pop(); !ok {
					break
				}
			}
			assert.True(t, q.isEmpty())
		})
	}
}
