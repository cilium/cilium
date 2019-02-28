// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/datapath/alignchecker"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		os.Exit(1)
	}

	bpfObjPath := os.Args[1]
	if _, err := os.Stat(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot check alignment against %s: %s\n", bpfObjPath, err)
		os.Exit(1)
	}
	if err := alignchecker.CheckStructAlignments(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "C and Go structs alignment check failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "OK\n")
}
