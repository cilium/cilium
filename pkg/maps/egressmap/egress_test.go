// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
)

func TestCell(t *testing.T) {
	err := hive.New(mapregistry.Cell, Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}
