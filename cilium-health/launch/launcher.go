// Copyright 2017 Authors of Cilium
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
	"os"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	healthPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/launcher"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CiliumHealth is used to wrap the node executable binary.
type CiliumHealth struct {
	launcher.Launcher
	client *healthPkg.Client
	status *models.Status
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-health-launcher")

	connectRetryInterval = 1 * time.Second
	statusProbeInterval  = 5 * time.Second
)

const targetName = "cilium-health"

// Run launches the cilium-health daemon.
func (ch *CiliumHealth) Run() {
	ch.SetTarget(targetName)
	ch.SetArgs([]string{"-d"})

	// Wait until Cilium API is available
	for {
		cli, err := ciliumPkg.NewDefaultClient()
		if err == nil {
			if _, err = cli.Daemon.GetHealthz(nil); err == nil {
				break
			}
		}
		log.WithError(err).Debugf("Cannot establish connection to local cilium instance")
		time.Sleep(connectRetryInterval)
	}

	for {
		var err error

		os.Remove(defaults.SockPath)
		ch.Launcher.Run()
		ch.client, err = healthPkg.NewDefaultClient()
		if err != nil {
			log.WithError(err).Infof("Cannot establish connection to local %s instance", targetName)
			ch.Launcher.Stop()
			time.Sleep(connectRetryInterval)
			continue
		}

		for {
			status := &models.Status{
				State: models.StatusStateOk,
			}
			if _, err := ch.client.Restapi.GetHello(nil); err != nil {
				status.Msg = ciliumPkg.Hint(err).Error()
				status.State = models.StatusStateWarning
			}
			ch.setStatus(status)
			time.Sleep(statusProbeInterval)
		}
	}
}

// GetStatus returns the status of the cilium-health daemon.
func (ch *CiliumHealth) GetStatus() *models.Status {
	ch.Mutex.RLock()
	status := ch.status
	ch.Mutex.RUnlock()
	return status
}

// setStatus updates the status of the cilium-health daemon.
func (ch *CiliumHealth) setStatus(status *models.Status) {
	ch.Mutex.Lock()
	ch.status = status
	ch.Mutex.Unlock()
}
