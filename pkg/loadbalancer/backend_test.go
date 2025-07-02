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
	assert.True(t, bytes.Equal(key.Key(), name.Key()), "BackendInstanceKey with prio 0 is the ServiceName key")
	key.SourcePriority = 1
	assert.True(t, bytes.HasPrefix(key.Key(), name.Key()), "BackendInstanceKey with prio 1 has ServiceName key as prefix")

	keyBytes := key.Key()
	suffix := keyBytes[len(name.Key()):]
	assert.Equal(t, []byte{' ', 1}, suffix, "suffix should be space + priority")
}
