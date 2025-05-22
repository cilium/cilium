// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/loader"
)

func main() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fmt.Println(strings.Join(loader.StandardCFlags, " ") + " -mcpu=" + loader.GetBPFCPU(logger))
}
