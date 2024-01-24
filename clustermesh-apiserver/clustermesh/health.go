// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

type HealthAPIServerConfig struct {
	ClusterMeshHealthPort int
}

func (HealthAPIServerConfig) Flags(flags *pflag.FlagSet) {
	flags.Int(option.ClusterMeshHealthPort, defaults.ClusterMeshHealthPort, "TCP port for ClusterMesh apiserver health API")
}

var healthAPIServerCell = cell.Module(
	"health-api-server",
	"ClusterMesh Health API Server",

	cell.Config(HealthAPIServerConfig{}),
	cell.Invoke(registerHealthAPIServer),
)

func registerHealthAPIServer(lc cell.Lifecycle, clientset k8sClient.Clientset, cfg HealthAPIServerConfig) {
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

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			go func() {
				log.Info("Started health API")
				if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					log.WithError(err).Fatal("Unable to start health API")
				}
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error { return srv.Shutdown(ctx) },
	})
}
