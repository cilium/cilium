/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"fmt"

	"k8s.io/apiserver/pkg/server/healthz"
)

// AddHealthzCheck allows you to add a HealthzCheck.
func (s *GenericAPIServer) AddHealthzChecks(checks ...healthz.HealthzChecker) error {
	s.healthzLock.Lock()
	defer s.healthzLock.Unlock()

	if s.healthzCreated {
		return fmt.Errorf("unable to add because the healthz endpoint has already been created")
	}

	s.healthzChecks = append(s.healthzChecks, checks...)
	return nil
}

// installHealthz creates the healthz endpoint for this server
func (s *GenericAPIServer) installHealthz() {
	s.healthzLock.Lock()
	defer s.healthzLock.Unlock()
	s.healthzCreated = true

	healthz.InstallHandler(s.Handler.NonGoRestfulMux, s.healthzChecks...)
}
