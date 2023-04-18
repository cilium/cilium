package cmd

import (
	"testing"

	"github.com/cilium/cilium/pkg/hive"
)

func TestAPIServerCell(t *testing.T) {
	h := hive.New(apiServerCell)
	h.Run()
}
