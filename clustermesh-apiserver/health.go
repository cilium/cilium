// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/spf13/pflag"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

type HealthAPIServerConfig struct {
	ClusterMeshHealthPort int
}

func (HealthAPIServerConfig) CellFlags(flags *pflag.FlagSet) {
	flags.Int(option.ClusterMeshHealthPort, defaults.ClusterMeshHealthPort, "TCP port for ClusterMesh apiserver health API")
}

var healthAPIServerCell = hive.NewCellWithConfig[HealthAPIServerConfig](
	"health-api-server",
	fx.Provide(newHealthAPIServer),
	fx.Invoke(func(HealthAPIServer) {}), // Always instantiate.
)

type HealthAPIServer struct {
	*http.Server
}

func newHealthAPIServer(lc fx.Lifecycle, clientset k8sClient.Clientset, cfg HealthAPIServerConfig) HealthAPIServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		statusCode := http.StatusOK
		reply := "ok"

		if _, err := clientset.Discovery().ServerVersion(); err != nil {
			statusCode = http.StatusInternalServerError
			reply = err.Error()
		}
		w.WriteHeader(statusCode)
		if _, err := w.Write([]byte(reply)); err != nil {
			log.WithError(err).Error("Failed to respond to /healthz request")
		}
	})

	srv := &http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", cfg.ClusterMeshHealthPort),
	}

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			go func() {
				log.Info("Started health API")
				if err := srv.ListenAndServe(); err != nil {
					log.WithError(err).Fatalf("Unable to start health API")
				}
			}()
			return nil
		},
		OnStop: srv.Shutdown,
	})

	return HealthAPIServer{srv}
}
