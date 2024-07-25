// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type handlersOut struct {
	cell.Out

	DaemonGetCgroupDumpMetadataHandler daemon.GetCgroupDumpMetadataHandler
	DaemonGetClusterNodesHandler       daemon.GetClusterNodesHandler
	DaemonGetDebuginfoHandler          daemon.GetDebuginfoHandler
	DaemonGetHealthzHandler            daemon.GetHealthzHandler
	DaemonGetMapHandler                daemon.GetMapHandler
	DaemonGetMapNameEventsHandler      daemon.GetMapNameEventsHandler
	DaemonGetMapNameHandler            daemon.GetMapNameHandler

	EndpointDeleteEndpointHandler        endpoint.DeleteEndpointHandler
	EndpointDeleteEndpointIDHandler      endpoint.DeleteEndpointIDHandler
	EndpointGetEndpointHandler           endpoint.GetEndpointHandler
	EndpointGetEndpointIDConfigHandler   endpoint.GetEndpointIDConfigHandler
	EndpointGetEndpointIDHandler         endpoint.GetEndpointIDHandler
	EndpointGetEndpointIDHealthzHandler  endpoint.GetEndpointIDHealthzHandler
	EndpointGetEndpointIDLabelsHandler   endpoint.GetEndpointIDLabelsHandler
	EndpointGetEndpointIDLogHandler      endpoint.GetEndpointIDLogHandler
	EndpointPatchEndpointIDConfigHandler endpoint.PatchEndpointIDConfigHandler
	EndpointPatchEndpointIDHandler       endpoint.PatchEndpointIDHandler
	EndpointPatchEndpointIDLabelsHandler endpoint.PatchEndpointIDLabelsHandler
	EndpointPutEndpointIDHandler         endpoint.PutEndpointIDHandler

	MetricsGetMetricsHandler metrics.GetMetricsHandler

	PolicyDeleteFqdnCacheHandler      policy.DeleteFqdnCacheHandler
	PolicyDeletePolicyHandler         policy.DeletePolicyHandler
	PolicyGetFqdnCacheHandler         policy.GetFqdnCacheHandler
	PolicyGetFqdnCacheIDHandler       policy.GetFqdnCacheIDHandler
	PolicyGetFqdnNamesHandler         policy.GetFqdnNamesHandler
	PolicyGetIdentityEndpointsHandler policy.GetIdentityEndpointsHandler
	PolicyGetIdentityHandler          policy.GetIdentityHandler
	PolicyGetIdentityIDHandler        policy.GetIdentityIDHandler
	PolicyGetIPHandler                policy.GetIPHandler
	PolicyGetPolicyHandler            policy.GetPolicyHandler
	PolicyGetPolicySelectorsHandler   policy.GetPolicySelectorsHandler
	PolicyPutPolicyHandler            policy.PutPolicyHandler

	ServiceDeleteServiceIDHandler service.DeleteServiceIDHandler
	ServiceGetServiceHandler      service.GetServiceHandler
	ServiceGetServiceIDHandler    service.GetServiceIDHandler
	ServicePutServiceIDHandler    service.PutServiceIDHandler
}

// apiHandler implements Handle() for the given parameter type.
// It allows expressing the API handlers requiring *Daemon as simply
// as a function of form `func(d *Daemon, p ParamType) middleware.Responder`.
// This wrapper takes care of Await'ing for *Daemon.
type apiHandler[Params any] struct {
	dp      promise.Promise[*Daemon]
	handler func(d *Daemon, p Params) middleware.Responder
}

func (a *apiHandler[Params]) Handle(p Params) middleware.Responder {
	// Wait for *Daemon to be ready. While 'p' would have a context, it's hard to get it
	// since it's a struct. Could use reflection, but since we'll stop the agent anyway
	// if daemon initialization fails it doesn't really matter that much here what context
	// to use.
	d, err := a.dp.Await(context.Background())
	if err != nil {
		return api.Error(http.StatusServiceUnavailable, err)
	}
	return a.handler(d, p)
}

func wrapAPIHandler[Params any](dp promise.Promise[*Daemon], handler func(d *Daemon, p Params) middleware.Responder) *apiHandler[Params] {
	return &apiHandler[Params]{dp: dp, handler: handler}
}

// apiHandlers bridges the API handlers still implemented inside Daemon into a set of
// individual handlers. Since NewDaemon() is side-effectful, we can only get a promise for
// *Daemon, and thus the handlers will need to Await() for it to be ready.
//
// This method depends on [deletionQueue] to make sure the deletion lock file is created and locked
// before the API server starts.
//
// This is meant to be a temporary measure until handlers have been moved out from *Daemon
// to daemon/restapi or feature-specific packages. At that point the dependency on *deletionQueue
// should be moved to the cell in daemon/restapi.
func ciliumAPIHandlers(dp promise.Promise[*Daemon], cfg *option.DaemonConfig, _ *deletionQueue) (out handlersOut) {
	// /healthz/
	out.DaemonGetHealthzHandler = wrapAPIHandler(dp, getHealthzHandler)

	// /service/
	out.ServiceGetServiceHandler = wrapAPIHandler(dp, getServiceHandler)

	// /service/{id}/
	out.ServiceGetServiceIDHandler = wrapAPIHandler(dp, getServiceIDHandler)
	out.ServiceDeleteServiceIDHandler = wrapAPIHandler(dp, deleteServiceIDHandler)
	out.ServicePutServiceIDHandler = wrapAPIHandler(dp, putServiceIDHandler)

	// /cluster/nodes
	out.DaemonGetClusterNodesHandler = NewGetClusterNodesHandler(dp)

	// /endpoint/
	out.EndpointDeleteEndpointHandler = wrapAPIHandler(dp, deleteEndpointHandler)
	out.EndpointGetEndpointHandler = wrapAPIHandler(dp, getEndpointHandler)

	// /endpoint/{id}
	out.EndpointGetEndpointIDHandler = wrapAPIHandler(dp, getEndpointIDHandler)
	out.EndpointPutEndpointIDHandler = wrapAPIHandler(dp, putEndpointIDHandler)
	out.EndpointPatchEndpointIDHandler = wrapAPIHandler(dp, patchEndpointIDHandler)
	out.EndpointDeleteEndpointIDHandler = wrapAPIHandler(dp, deleteEndpointIDHandler)

	// /endpoint/{id}config/
	out.EndpointGetEndpointIDConfigHandler = wrapAPIHandler(dp, getEndpointIDConfigHandler)
	out.EndpointPatchEndpointIDConfigHandler = wrapAPIHandler(dp, patchEndpointIDConfigHandler)

	// /endpoint/{id}/labels/
	out.EndpointGetEndpointIDLabelsHandler = wrapAPIHandler(dp, getEndpointIDLabelsHandler)
	out.EndpointPatchEndpointIDLabelsHandler = wrapAPIHandler(dp, putEndpointIDLabelsHandler)

	// /endpoint/{id}/log/
	out.EndpointGetEndpointIDLogHandler = wrapAPIHandler(dp, getEndpointIDLogHandler)

	// /endpoint/{id}/healthz
	out.EndpointGetEndpointIDHealthzHandler = wrapAPIHandler(dp, getEndpointIDHealthzHandler)

	// /identity/
	out.PolicyGetIdentityHandler = wrapAPIHandler(dp, getIdentityHandler)
	out.PolicyGetIdentityIDHandler = wrapAPIHandler(dp, getIdentityIDHandler)

	// /identity/endpoints
	out.PolicyGetIdentityEndpointsHandler = wrapAPIHandler(dp, getIdentityEndpointsHandler)

	// /policy/
	out.PolicyGetPolicyHandler = wrapAPIHandler(dp, getPolicyHandler)
	out.PolicyPutPolicyHandler = wrapAPIHandler(dp, putPolicyHandler)
	out.PolicyDeletePolicyHandler = wrapAPIHandler(dp, deletePolicyHandler)
	out.PolicyGetPolicySelectorsHandler = wrapAPIHandler(dp, getPolicySelectorsHandler)

	// /debuginfo
	out.DaemonGetDebuginfoHandler = wrapAPIHandler(dp, getDebugInfoHandler)

	// /cgroup-dump-metadata
	out.DaemonGetCgroupDumpMetadataHandler = wrapAPIHandler(dp, getCgroupDumpMetadataHandler)

	// /map
	out.DaemonGetMapHandler = wrapAPIHandler(dp, getMapHandler)
	out.DaemonGetMapNameHandler = wrapAPIHandler(dp, getMapNameHandler)
	out.DaemonGetMapNameEventsHandler = wrapAPIHandler(dp, getMapNameEventsHandler)

	// metrics
	out.MetricsGetMetricsHandler = wrapAPIHandler(dp, getMetricsHandler)

	// /fqdn/cache
	out.PolicyGetFqdnCacheHandler = wrapAPIHandler(dp, getFqdnCacheHandler)
	out.PolicyDeleteFqdnCacheHandler = wrapAPIHandler(dp, deleteFqdnCacheHandler)
	out.PolicyGetFqdnCacheIDHandler = wrapAPIHandler(dp, getFqdnCacheIDHandler)
	out.PolicyGetFqdnNamesHandler = wrapAPIHandler(dp, getFqdnNamesHandler)

	// /ip/
	out.PolicyGetIPHandler = wrapAPIHandler(dp, getIPHandler)

	return
}
