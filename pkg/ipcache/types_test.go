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
	pi := newPrefixInfo()
	pim := pi.byResource
	pim["a-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pim["b-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pim["node-uid"] = &resourceInfo{
		source: source.CustomResource,
	}
	pim["node2-uid"] = &resourceInfo{
		source: source.Local,
	}
	pim["daemon-uid"] = &resourceInfo{
		source: source.Local,
	}
	pim["endpoints-uid"] = &resourceInfo{
		source: source.KubeAPIServer,
	}
	pim["2-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pim["1-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pim["generated-uid"] = &resourceInfo{
		source: source.Generated,
	}
	pim["kvstore-uid"] = &resourceInfo{
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
