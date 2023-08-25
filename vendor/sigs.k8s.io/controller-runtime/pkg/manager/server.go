/*
Copyright 2022 The Kubernetes Authors.

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

package manager

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/go-logr/logr"
)

// server is a general purpose HTTP server Runnable for a manager
// to serve some internal handlers such as health probes, metrics and profiling.
type server struct {
	Kind     string
	Log      logr.Logger
	Server   *http.Server
	Listener net.Listener
}

func (s *server) Start(ctx context.Context) error {
	log := s.Log.WithValues("kind", s.Kind, "addr", s.Listener.Addr())

	serverShutdown := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("shutting down server")
		if err := s.Server.Shutdown(context.Background()); err != nil {
			log.Error(err, "error shutting down server")
		}
		close(serverShutdown)
	}()

	log.Info("starting server")
	if err := s.Server.Serve(s.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	<-serverShutdown
	return nil
}

func (s *server) NeedLeaderElection() bool {
	return false
}
