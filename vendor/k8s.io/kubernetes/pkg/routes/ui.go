/*
Copyright 2014 The Kubernetes Authors.

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

package routes

import (
	"net/http"

	"k8s.io/apiserver/pkg/server/mux"
)

const dashboardPath = "/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy"

// UIRediect redirects /ui to the kube-ui proxy path.
type UIRedirect struct{}

func (r UIRedirect) Install(c *mux.PathRecorderMux) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dashboardPath, http.StatusTemporaryRedirect)
	})
	c.Handle("/ui", handler)
	c.HandlePrefix("/ui/", handler)
}
