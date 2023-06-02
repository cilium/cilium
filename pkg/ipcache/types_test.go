// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/source"
)

func Test_sortedByResourceIDsAndSource(t *testing.T) {
	pi := make(PrefixInfo, 1)
	pi["a-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pi["b-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pi["node-uid"] = &resourceInfo{
		source: source.CustomResource,
	}
	pi["node2-uid"] = &resourceInfo{
		source: source.Local,
	}
	pi["daemon-uid"] = &resourceInfo{
		source: source.Local,
	}
	pi["endpoints-uid"] = &resourceInfo{
		source: source.KubeAPIServer,
	}
	pi["2-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pi["1-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pi["generated-uid"] = &resourceInfo{
		source: source.Generated,
	}
	pi["kvstore-uid"] = &resourceInfo{
		source: source.KVStore,
	}

	expected := []types.ResourceID{
		"endpoints-uid",
		"daemon-uid",
		"node2-uid",
		"kvstore-uid",
		"node-uid",
		"1-identity-uid",
		"2-identity-uid",
		"generated-uid",
		"a-restored-uid",
		"b-restored-uid",
	}
	assert.Equal(t, expected, pi.sortedBySourceThenResourceID())
}
