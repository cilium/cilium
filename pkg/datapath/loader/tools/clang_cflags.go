// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/loader"
)

func main() {
	fmt.Println(strings.Join(loader.StandardCFlags, " "))
}
