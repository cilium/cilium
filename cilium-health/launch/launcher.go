// Copyright 2017-2019 Authors of Cilium
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

package launch

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/health/server"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// CiliumHealth launches and polls the cilium-health daemon
type CiliumHealth struct {
	mutex  lock.RWMutex
	server *server.Server
	client *client.Client
	status *models.Status
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-health-launcher")

const (
	serverProbeInterval  = 60 * time.Second
	serverProbeDeadline  = 1 * time.Second
	connectRetryInterval = 1 * time.Second
	statusProbeInterval  = 5 * time.Second
)

// Launch starts the cilium-health server and returns a handle to obtain its status
func Launch() (*CiliumHealth, error) {
	var (
		err error
		ch  = &CiliumHealth{}
	)

	config := server.Config{
		Debug:         option.Config.Opts.IsEnabled(option.Debug),
		ProbeInterval: serverProbeInterval,
		ProbeDeadline: serverProbeDeadline,
	}

	ch.server, err = server.NewServer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cilium-health server: %s", err)
	}

	ch.client, err = client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cilium-health client: %s", err)
	}

	go ch.runServer()

	return ch, nil
}

func (ch *CiliumHealth) runServer() {
	// Wait until Cilium API is available
	for {
		cli, err := ciliumPkg.NewDefaultClient()
		if err == nil {
			// Making sure that we can talk with the daemon.
			if _, err = cli.Daemon.GetHealthz(nil); err == nil {
				break
			}
		}
		log.WithError(err).Debugf("Cannot establish connection to local cilium instance")
		time.Sleep(connectRetryInterval)
	}

	// Launch cilium-health API server
	os.Remove(defaults.SockPath)
	go func() {
		defer ch.server.Shutdown()
		if err := ch.server.Serve(); err != nil {
			log.WithError(err).Error("Failed to serve cilium-health API")
		}
	}()

	// When the unix socket is made available, set its permissions.
	scopedLog := log.WithField(logfields.Path, defaults.SockPath)
	for {
		_, err := os.Stat(defaults.SockPath)
		if err == nil {
			break
		}
		scopedLog.WithError(err).Debugf("Cannot find socket")
		time.Sleep(1 * time.Second)
	}
	if err := api.SetDefaultPermissions(defaults.SockPath); err != nil {
		scopedLog.WithError(err).Fatal("Cannot set default permissions on socket")
	}

	// Periodically fetch status from cilium-health server
	for {
		status := &models.Status{
			State: models.StatusStateOk,
		}

		_, err := ch.client.Restapi.GetHealthz(nil)
		if err != nil {
			status.Msg = err.Error()
			status.State = models.StatusStateWarning
		}

		ch.setStatus(status)
		time.Sleep(statusProbeInterval)
	}
}

// GetStatus returns the status of the cilium-health daemon.
func (ch *CiliumHealth) GetStatus() *models.Status {
	ch.mutex.RLock()
	status := ch.status
	ch.mutex.RUnlock()
	return status
}

// setStatus updates the status of the cilium-health daemon.
func (ch *CiliumHealth) setStatus(status *models.Status) {
	ch.mutex.Lock()
	ch.status = status
	ch.mutex.Unlock()
}
