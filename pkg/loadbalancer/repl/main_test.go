// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"testing"

	"github.com/cilium/hive/hivetest"
)

func TestHive(t *testing.T) {
	if err := Hive.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("Populate: %s", err)
	}
}
