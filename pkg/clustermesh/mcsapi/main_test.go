// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}
