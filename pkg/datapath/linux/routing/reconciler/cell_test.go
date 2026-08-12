// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"testing"

	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func TestIsCloudIPAMMode(t *testing.T) {
	require.True(t, isCloudIPAMMode(ipamOption.IPAMENI))
	require.True(t, isCloudIPAMMode(ipamOption.IPAMAzure))
	require.False(t, isCloudIPAMMode(ipamOption.IPAMAlibabaCloud))
	require.False(t, isCloudIPAMMode(ipamOption.IPAMClusterPool))
}
