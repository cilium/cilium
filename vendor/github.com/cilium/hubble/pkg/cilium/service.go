// Copyright 2020 Authors of Hubble
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

package cilium

import (
	"encoding/json"
	"time"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/sirupsen/logrus"
)

const (
	serviceCacheInitRetryInterval = 5 * time.Second
	serviceCacheRefreshInterval   = 5 * time.Minute
)

// fetchServiceCache fetches the service cache from cilium and initializes the
// local service cache.
func (s *State) fetchServiceCache() error {
	entries, err := s.ciliumClient.GetServiceCache()
	if err != nil {
		return err
	}
	if err := s.serviceCache.InitializeFrom(entries); err != nil {
		return err
	}
	s.log.WithField("entries", len(entries)).Debug("Fetched service cache from cilium")
	return nil
}

// processServiceEvent decodes and applies a service update. It returns true
// when successful.
func (s *State) processServiceEvent(an monitorAPI.AgentNotify) bool {
	switch an.Type {
	case monitorAPI.AgentNotifyServiceUpserted:
		n := monitorAPI.ServiceUpsertNotification{}
		if err := json.Unmarshal([]byte(an.Text), &n); err != nil {
			s.log.WithFields(logrus.Fields{
				"type":                      int(an.Type),
				"ServiceUpsertNotification": an.Text,
			}).Error("Unable to unmarshal service upsert notification")
			return false
		}
		return s.serviceCache.Upsert(int64(n.ID), n.Name, n.Type, n.Namespace, n.Frontend.IP, n.Frontend.Port)
	case monitorAPI.AgentNotifyServiceDeleted:
		n := monitorAPI.ServiceDeleteNotification{}
		if err := json.Unmarshal([]byte(an.Text), &n); err != nil {
			s.log.WithFields(logrus.Fields{
				"type":                      int(an.Type),
				"ServiceDeleteNotification": an.Text,
			}).Error("Unable to unmarshal service delete notification")
			return false
		}
		return s.serviceCache.DeleteByID(int64(n.ID))
	default:
		s.log.WithField("type", int(an.Type)).Warn("Received unknown service notification type")
		return false
	}
}

func (s *State) syncServiceCache(serviceEvents <-chan monitorAPI.AgentNotify) {
	for err := s.fetchServiceCache(); err != nil; err = s.fetchServiceCache() {
		s.log.WithError(err).Error("Failed to fetch service cache from Cilium")
		time.Sleep(serviceCacheInitRetryInterval)
	}

	refresh := time.NewTimer(serviceCacheInitRetryInterval)
	inSync := false

	for serviceEvents != nil {
		select {
		case <-refresh.C:
			if err := s.fetchServiceCache(); err != nil {
				s.log.WithError(err).Error("Failed to fetch service cache from Cilium")
			}
			refresh.Reset(serviceCacheInitRetryInterval)
		case an, ok := <-serviceEvents:
			if !ok {
				return
			}
			// Initially we might see stale updates that were enqued before we
			// initialized the service cache.
			// Once we see the first applicable update though, all subsequent
			// updates must be applicable as well.
			updated := s.processServiceEvent(an)
			switch {
			case !updated && !inSync:
				s.log.WithFields(logrus.Fields{
					"type":              int(an.Type),
					"AgentNotification": an.Text,
				}).Debug("Received stale service update")
			case !updated && inSync:
				s.log.WithFields(logrus.Fields{
					"type":              int(an.Type),
					"AgentNotification": an.Text,
				}).Warn("Received unapplicable service update")
			case updated && !inSync:
				inSync = true
			}
		}
	}
}
