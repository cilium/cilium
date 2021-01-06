// Copyright 2018-2019 Authors of Cilium
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

package api

import (
	"net/http"
	"os"
	"runtime/debug"

	"github.com/cilium/cilium/pkg/logging"

	"github.com/sirupsen/logrus"
)

// APIPanicHandler recovers from API panics and logs encountered panics
type APIPanicHandler struct {
	Next http.Handler
}

// ServeHTTP implements the http.Handler interface.
// It recovers from panics of all next handlers and logs them
func (h *APIPanicHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			fields := logrus.Fields{
				"panic_message": r,
				"url":           req.URL.String(),
				"method":        req.Method,
				"client":        req.RemoteAddr,
			}
			log.WithFields(fields).Warn("Cilium API handler panicked")
			if logging.DefaultLogger.IsLevelEnabled(logrus.DebugLevel) {
				os.Stdout.Write(debug.Stack())
			}
			wr.WriteHeader(http.StatusInternalServerError)
			if _, err := wr.Write([]byte("Internal error occurred, check Cilium logs for details.")); err != nil {
				log.WithError(err).Debug("Failed to write API response")
			}
		}
	}()
	h.Next.ServeHTTP(wr, req)
}
