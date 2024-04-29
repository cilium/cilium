// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

type HealthAPIServerConfig struct {
	HealthPort int
}

func (def HealthAPIServerConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("health-port", def.HealthPort, "TCP port for ClusterMesh health API")
}

var DefaultHealthAPIServerConfig = HealthAPIServerConfig{
	HealthPort: 9880,
}

var HealthAPIServerCell = cell.Module(
	"health-api-server",
	"ClusterMesh Health API Server",

	cell.Config(DefaultHealthAPIServerConfig),
	cell.Invoke(registerHealthAPIServer),
)

type parameters struct {
	cell.In

	Config        HealthAPIServerConfig
	Logger        logrus.FieldLogger
	EndpointFuncs []EndpointFunc
}

type EndpointFunc struct {
	Path        string
	HandlerFunc http.HandlerFunc
}

func registerHealthAPIServer(lc cell.Lifecycle, params parameters) {
	mux := http.NewServeMux()

	for _, endpoint := range params.EndpointFuncs {
		mux.HandleFunc(endpoint.Path, endpoint.HandlerFunc)
	}

	srv := &http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", params.Config.HealthPort),
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			go func() {
				params.Logger.Info("Started health API")
				if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					params.Logger.WithError(err).Fatal("Unable to start health API")
				}
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error { return srv.Shutdown(ctx) },
	})
}
