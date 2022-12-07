package main

import (
	"github.com/cilium/customvet/analysis/ioreadall"
	"github.com/cilium/customvet/analysis/timeafter"

	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(timeafter.Analyzer, ioreadall.Analyzer)
}
