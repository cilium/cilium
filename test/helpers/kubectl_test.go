// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseHelmOverrides(t *testing.T) {
	// This should be able to parse key value pairs, including those
	// where the value has commas but is delimited by quotes.
	overridesStr := "key1=value1,\"key2={a,b,c}\",\"key3={}\""
	expected := map[string]string{
		"key1": "value1",
		"key2": "{a,b,c}",
		"key3": "{}",
	}
	overrides := map[string]string{}
	parseHelmOverrides(overridesStr, overrides)
	assert.Equal(t, expected, overrides)
}
