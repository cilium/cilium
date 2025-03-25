// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestICMPFieldUnmarshal(t *testing.T) {
	setUpSuite(t)

	var i ICMPField

	value1 := []byte("{\"family\": \"IPv4\", \"type\": 8}")
	err := json.Unmarshal(value1, &i)

	icmpType := intstr.FromInt(8)
	require.Equal(t, ICMPField{Family: IPv4Family, Type: &icmpType}, i)
	require.NoError(t, err)

	// Check ICMPFIeld can treat ICMP type name
	value2 := []byte("{\"family\": \"IPv4\", \"type\": \"EchoRequest\"}")
	err = json.Unmarshal(value2, &i)

	icmpType = intstr.FromString("EchoRequest")
	require.Equal(t, ICMPField{Family: IPv4Family, Type: &icmpType}, i)
	require.NoError(t, err)

	// ICMP Node Information Query is only for IPv6
	value3 := []byte("{\"family\": \"IPv4\", \"type\": \"ICMPNodeInformationQuery\"}")
	err = json.Unmarshal(value3, &i)

	require.Error(t, err)
}
