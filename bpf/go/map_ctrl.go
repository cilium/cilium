//
// Copyright 2016 Authors of Cilium
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
//
package main

/*
#cgo CFLAGS: -I../include
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cilium/cilium/common/bpf"

	"github.com/codegangsta/cli"
)

func printArgsUsage(ctx *cli.Context) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s %s\n", ctx.App.Name, ctx.Command.Name,
		ctx.Command.ArgsUsage)
}

func main() {
	app := cli.NewApp()
	app.Name = "map-ctrl"
	app.Usage = "eBPF Control MAP"
	app.Version = "0.0.1"
	app.Commands = []cli.Command{
		{
			Name:      "dump",
			Aliases:   []string{"d"},
			Usage:     "dumps map present on the given <map file>",
			ArgsUsage: "<map file>",
			Action:    dumpMap,
		},
		{
			Name:      "info",
			Aliases:   []string{"i"},
			Usage:     "Print information about a given <map file>",
			ArgsUsage: "<map file>",
			Action:    infoMap,
		},
	}

	app.Run(os.Args)
}

func dumpMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		printArgsUsage(ctx)
		os.Exit(1)
	}

	file := ctx.Args().Get(0)

	m, err := bpf.OpenMap(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	dumpit := func(key []byte, value []byte) {
		fmt.Printf("Key:%sValue:\n%s", hex.Dump(key), hex.Dump(value))
	}

	err = m.Dump(dumpit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func infoMap(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		printArgsUsage(ctx)
		os.Exit(1)
	}

	file := ctx.Args().Get(0)

	m, err := bpf.OpenMap(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Type:\t\t%s\nKey size:\t%d\nValue size:\t%d\nMax entries:\t%d\n",
		m.MapType.String(), m.KeySize, m.ValueSize, m.MaxEntries)
}
