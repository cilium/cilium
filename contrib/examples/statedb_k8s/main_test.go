package main

import (
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

// TestExampleHive checks that the example compiles and the
// dependencies can be wired up.
func TestExampleHive(t *testing.T) {
	err := hive.New(app).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatalf("Populate failed: %s", err)
	}
}
