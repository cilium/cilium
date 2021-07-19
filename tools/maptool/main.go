// Copyright 2019-2021 Authors of Cilium
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
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
)

type mapCreationFunc func(string) error

var mapBuilders = map[string]mapCreationFunc{
	"eppolicymap": eppolicymap.CreateWithName,
	"sockmap":     sockmap.CreateWithName,
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <type> <path>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "TYPE :=")
	separator := " "
	for k := range mapBuilders {
		fmt.Fprintf(os.Stderr, "%s%s", separator, strings.ToUpper(k))
		separator = " | "
	}
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		usage()
	}

	mapType := os.Args[1]
	createMap, exists := mapBuilders[strings.ToLower(mapType)]
	if !exists {
		fmt.Fprintf(os.Stderr, "Unrecognized map type %s\n", mapType)
		usage()
	}

	if err := bpf.ConfigureResourceLimits(); err != nil {
		fmt.Fprintf(os.Stdout, "Failed to configure resource limits: %s\n", err)
	}
	bpf.CheckOrMountFS("")

	bpfObjPath := os.Args[2]
	if err := createMap(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stdout, "Failed to create map: %s\n", err)
	}
}
