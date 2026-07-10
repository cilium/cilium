// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}
