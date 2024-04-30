// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestAutoDetect(t *testing.T) {
	testutils.PrivilegedTest(t)

	mtu, err := autoDetect()
	require.Nil(t, err)
	require.NotEqual(t, 0, mtu)
}
