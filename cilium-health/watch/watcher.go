// Copyright 2017-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CiliumHealth is used to watch the cilium-health deamon by communication
// through client.
type CiliumHealth struct {
	client *healthPkg.Client
	mutex  lock.RWMutex
	status *models.Status
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-health-launcher")

	connectRetryInterval = 1 * time.Second
	statusProbeInterval  = 5 * time.Second
)

// Watch watches the cilium-health daemon.
func (ch *CiliumHealth) Watch() {
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
		ch.client, err = healthPkg.NewDefaultClient()
		if err != nil {
			log.WithError(err).Infof("Cannot establish connection to local cilium-health instance")
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
