// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewNodeHandler(t *testing.T) {
	nh := NewHandler()
	require.NotNil(t, nh)

}
