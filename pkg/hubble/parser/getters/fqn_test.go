// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFQN(t *testing.T) {
	uu := map[string]struct {
		name      string
		namespace string
		e         FQN
	}{
		"blank": {
			e: BlankFQN,
		},

		"namespace only": {
			namespace: "ns",
			e:         NewFQN("ns", ""),
		},

		"name only": {
			name: "name",
			e:    NewFQN("", "name"),
		},

		"full": {
			namespace: "ns",
			name:      "name",
			e:         NewFQN("ns", "name"),
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			fqn := NewFQN(u.namespace, u.name)
			assert.Equal(t, u.e, fqn)
		})
	}
}

func TestFQNIsBlank(t *testing.T) {
	uu := map[string]struct {
		fqn FQN
		e   bool
	}{
		"empty": {
			fqn: FQN{},
			e:   true,
		},

		"blank": {
			fqn: BlankFQN,
			e:   true,
		},

		"namespace only": {
			fqn: NewFQN("ns", ""),
		},

		"name only": {
			fqn: NewFQN("", "name"),
		},

		"full": {
			fqn: NewFQN("ns", "name"),
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.fqn.IsBlank())
		})
	}
}
