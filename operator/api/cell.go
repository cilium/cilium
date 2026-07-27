// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// OperatorAPIServeAddr is the "<ip>:<port>" on which to serve api requests
	// from the operator.
	// Use ":<port>" to bind on all interfaces.
	// Use an empty string to bind on both "127.0.0.1:0" and "[::1]:0".
	OperatorAPIServeAddr = "operator-api-serve-addr"
)

const (
	// OperatorAPIServeAddrDefault is the default "<ip>:<port>" value on which to serve
	// api requests from the operator.
	OperatorAPIServeAddrDefault = "localhost:9234"
)

var ServerCell = cell.Module(
	"cilium-operator-api",
	"Cilium Operator API Server",

	cell.Config(defaultConfig),
	cell.Provide(newServer),
	cell.Invoke(func(Server) {}),
)

type Config struct {
	OperatorAPIServeAddr string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(OperatorAPIServeAddr, def.OperatorAPIServeAddr, "Address to serve API requests")
}

var defaultConfig = Config{
	OperatorAPIServeAddr: OperatorAPIServeAddrDefault,
}
