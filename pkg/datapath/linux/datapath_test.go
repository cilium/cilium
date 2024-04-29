// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDatapath(t *testing.T) {
	dp := NewDatapath(DatapathParams{})
	require.NotNil(t, dp)
}
