// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	operatorHive := hive.New(cmd.Operator)

	cmd.Execute(cmd.NewOperatorCmd(operatorHive))
}
