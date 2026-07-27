// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(NewAnalyzer())
}
