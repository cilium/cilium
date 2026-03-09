// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func checkMarshalUnmarshal(t *testing.T, r *Rule) {
	jsonData, err := json.Marshal(r)
	require.NoError(t, err)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	require.NoError(t, err)

	require.Equal(t, newRule.EndpointSelector.LabelSelector == nil, r.EndpointSelector.LabelSelector == nil)
	require.Equal(t, newRule.NodeSelector.LabelSelector == nil, r.NodeSelector.LabelSelector == nil)
}

// This test ensures that the NodeSelector and EndpointSelector fields are kept
// empty when the rule is marshalled/unmarshalled.
func TestJSONMarshalling(t *testing.T) {
	validEndpointRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validEndpointRule)

	validNodeRule := Rule{
		NodeSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(t, &validNodeRule)
}
