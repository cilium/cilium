// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackendInstanceKey(t *testing.T) {
	name := NewServiceNameInCluster("foo", "bar", "baz")
	key := BackendInstanceKey{
		ServiceName:    name,
		SourcePriority: 0,
	}
	nameExtended := NewServiceNameInCluster("foo", "bar", "baz-extended")
	keyExtended := BackendInstanceKey{
		ServiceName:    nameExtended,
		SourcePriority: 0,
	}

	assert.True(t, bytes.Equal(key.Key(), append(name.Key(), ' ')), "BackendInstanceKey with prio 0 is the ServiceName key + ' '")
	assert.False(t, bytes.HasPrefix(key.Key(), keyExtended.Key()), "BackendInstanceKey with prio 0 should not have the the same prefix if the prefix of one service is the name of another service")
	key.SourcePriority = 1
	assert.True(t, bytes.HasPrefix(key.Key(), name.Key()), "BackendInstanceKey with prio 1 has ServiceName key as prefix")

	keyBytes := key.Key()
	suffix := keyBytes[len(name.Key()):]
	assert.Equal(t, []byte{' ', 1}, suffix, "suffix should be space + priority")
}
