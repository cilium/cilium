// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"fmt"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/swag"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/kvstoremesh/server"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// DefaultAPIServeAddr is the default address the KVStoreMesh API is served on.
const DefaultAPIServeAddr = "localhost:9889"

type apiServerConfig struct {
	APIServeAddr string
}

func (def apiServerConfig) Flags(flags *pflag.FlagSet) {
	flags.String("api-serve-addr", def.APIServeAddr, "Address to serve the KVStoreMesh API")
}

var APIServerCell = cell.Module(
	"kvstoremesh-api-server",
	"KVStoreMesh API Server",

	server.Cell,

	cell.Config(apiServerConfig{APIServeAddr: DefaultAPIServeAddr}),
	cell.Provide(apiServerSpec),
	cell.Invoke(configureAPIServer),
)

// Reduced version of server.Spec, which doesn't allow to administratively disable
// APIs, as overkill in this context, and registering an unnecessary flag.
func apiServerSpec() (*server.Spec, error) {
	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load swagger spec: %w", err)
	}
	return &server.Spec{Document: swaggerSpec}, nil
}

func configureAPIServer(s *server.Server, cfg apiServerConfig) error {
	host, port, err := swag.SplitHostPort(cfg.APIServeAddr)
	if err != nil {
		return fmt.Errorf("failed to configure API Server: %w", err)
	}

	s.EnabledListeners = []string{"http"}
	s.Host = host
	s.Port = port
	return nil
}
