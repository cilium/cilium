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
	"net"
	"net/http"

	"github.com/golang/glog"

	"k8s.io/apiserver/pkg/authentication/user"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/rest"
)

// InsecureServingInfo is required to serve http.  HTTP does NOT include authentication or authorization.
// You shouldn't be using this.  It makes sig-auth sad.
// InsecureServingInfo *ServingInfo

func BuildInsecureHandlerChain(apiHandler http.Handler, c *server.Config) http.Handler {
	handler := apiHandler
	if utilfeature.DefaultFeatureGate.Enabled(features.AdvancedAuditing) {
		handler = genericapifilters.WithAudit(handler, c.RequestContextMapper, c.AuditBackend, c.AuditPolicyChecker, c.LongRunningFunc)
	} else {
		handler = genericapifilters.WithLegacyAudit(handler, c.RequestContextMapper, c.LegacyAuditWriter)
	}
	handler = genericapifilters.WithAuthentication(handler, c.RequestContextMapper, insecureSuperuser{}, nil)
	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")
	handler = genericfilters.WithPanicRecovery(handler)
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.RequestContextMapper, c.LongRunningFunc, c.RequestTimeout)
	handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.RequestContextMapper, c.LongRunningFunc)
	handler = genericapifilters.WithRequestInfo(handler, server.NewRequestInfoResolver(c), c.RequestContextMapper)
	handler = apirequest.WithRequestContext(handler, c.RequestContextMapper)

	return handler
}

type InsecureServingInfo struct {
	// BindAddress is the ip:port to serve on
	BindAddress string
	// BindNetwork is the type of network to bind to - defaults to "tcp", accepts "tcp",
	// "tcp4", and "tcp6".
	BindNetwork string
}

func (s *InsecureServingInfo) NewLoopbackClientConfig(token string) (*rest.Config, error) {
	if s == nil {
		return nil, nil
	}

	host, port, err := server.LoopbackHostPort(s.BindAddress)
	if err != nil {
		return nil, err
	}

	return &rest.Config{
		Host: "http://" + net.JoinHostPort(host, port),
		// Increase QPS limits. The client is currently passed to all admission plugins,
		// and those can be throttled in case of higher load on apiserver - see #22340 and #22422
		// for more details. Once #22422 is fixed, we may want to remove it.
		QPS:   50,
		Burst: 100,
	}, nil
}

// NonBlockingRun spawns the insecure http server. An error is
// returned if the ports cannot be listened on.
func NonBlockingRun(insecureServingInfo *InsecureServingInfo, insecureHandler http.Handler, stopCh <-chan struct{}) error {
	// Use an internal stop channel to allow cleanup of the listeners on error.
	internalStopCh := make(chan struct{})

	if insecureServingInfo != nil && insecureHandler != nil {
		if err := serveInsecurely(insecureServingInfo, insecureHandler, internalStopCh); err != nil {
			close(internalStopCh)
			return err
		}
	}

	// Now that the listener has bound successfully, it is the
	// responsibility of the caller to close the provided channel to
	// ensure cleanup.
	go func() {
		<-stopCh
		close(internalStopCh)
	}()

	return nil
}

// serveInsecurely run the insecure http server. It fails only if the initial listen
// call fails. The actual server loop (stoppable by closing stopCh) runs in a go
// routine, i.e. serveInsecurely does not block.
func serveInsecurely(insecureServingInfo *InsecureServingInfo, insecureHandler http.Handler, stopCh <-chan struct{}) error {
	insecureServer := &http.Server{
		Addr:           insecureServingInfo.BindAddress,
		Handler:        insecureHandler,
		MaxHeaderBytes: 1 << 20,
	}
	glog.Infof("Serving insecurely on %s", insecureServingInfo.BindAddress)
	var err error
	_, err = server.RunServer(insecureServer, insecureServingInfo.BindNetwork, stopCh)
	return err
}

// insecureSuperuser implements authenticator.Request to always return a superuser.
// This is functionally equivalent to skipping authentication and authorization,
// but allows apiserver code to stop special-casing a nil user to skip authorization checks.
type insecureSuperuser struct{}

func (insecureSuperuser) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	return &user.DefaultInfo{
		Name:   "system:unsecured",
		Groups: []string{user.SystemPrivilegedGroup, user.AllAuthenticated},
	}, true, nil
}
