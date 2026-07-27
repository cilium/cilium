// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/cilium/cilium/tools/metricslint/pkg/analyzer"
)

func main() {
	singlechecker.Main(analyzer.Analyzer)
}
