// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sync"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/rate"
)

var endpointHandlersCell = cell.Module(
	"cilium-restapi-endpoints",
	"Cilium API handlers for endpoints",

	cell.Provide(newEndpointHandlers),
	cell.ProvidePrivate(
		func(em endpointmanager.EndpointManager) endpointLookup {
			return em
		},
	),
)

// endpointLookup is the subset of methods in EndpointManager used by the
// handlers.
//
// Note that modifications to endpoints still go mostly via EndpointModifier
// implemented by cmd.Daemon.
type endpointLookup interface {
	GetEndpoints() []*endpoint.Endpoint
	Lookup(id string) (*endpoint.Endpoint, error)
	UpdateReferences(ep *endpoint.Endpoint) error
}

// endpointGetHandlerParams are the common set of parameters shared
// by the endpoint GET handlers.
type endpointGetHandlerParams struct {
	cell.In

	Log       logrus.FieldLogger
	Endpoints endpointLookup
	RateLimit *rate.APILimiterSet
}

// endpointModifyHandlerParams are the common set of parameters shared
// by the endpoint POST/PATCH/PUT handlers.
type endpointModifyHandlerParams struct {
	cell.In

	Log       logrus.FieldLogger
	Endpoints endpointLookup
	RateLimit *rate.APILimiterSet

	EndpointModifierPromise promise.Promise[EndpointModifier]
}

// EndpointModifier is implemented by the daemon to create or modify an endpoint.
// These operations still have many dependencies to daemon-owned components so
// the code cannot yet easily be migrated here.
type EndpointModifier interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (int, error)
	PatchEndpoint(ctx context.Context, ID string, epTemplate *models.EndpointChangeRequest) (int, error)
	DeleteEndpoint(id string) (int, error)
}

type endpointHandlersOut struct {
	cell.Out

	GetEndpointHandler          endpointapi.GetEndpointHandler          // GET /endpoint (with labels)
	GetEndpointIDHandler        endpointapi.GetEndpointIDHandler        // GET /endpoint/{id}
	GetEndpointIDConfigHandler  endpointapi.GetEndpointIDConfigHandler  // GET /endpoint/{id}/config
	GetEndpointIDLabelsHandler  endpointapi.GetEndpointIDLabelsHandler  // GET /endpoint/{id}/labels
	GetEndpointIDLogHandler     endpointapi.GetEndpointIDLogHandler     // GET /endpoint/{id}/log
	GetEndpointIDHealthzHandler endpointapi.GetEndpointIDHealthzHandler // GET /endpoint/{id}/healthz

	DeleteEndpointIDHandler      endpointapi.DeleteEndpointIDHandler      // DELETE /endpoint/{id}
	PutEndpointIDHandler         endpointapi.PutEndpointIDHandler         // PUT /endpoint/{id}
	PatchEndpointIDHandler       endpointapi.PatchEndpointIDHandler       // PATCH /endpoint/{id}
	PatchEndpointIDLabelsHandler endpointapi.PatchEndpointIDLabelsHandler // PATCH /endpoint/{id}/labels
	PatchEndpointIDConfigHandler endpointapi.PatchEndpointIDConfigHandler // PATCH /endpoint/{id}/config
}

// Since all the handlers share the same set of parameters and hold
// no state, we can just new type around the input parameters to
// implement Handle() for each of them.
type (
	getEndpointHandler          endpointGetHandlerParams
	getEndpointIDHandler        endpointGetHandlerParams
	getEndpointIDConfigHandler  endpointGetHandlerParams
	getEndpointIDLabelsHandler  endpointGetHandlerParams
	getEndpointIDLogHandler     endpointGetHandlerParams
	getEndpointIDHealthzHandler endpointGetHandlerParams

	deleteEndpointHandler        endpointModifyHandlerParams
	putEndpointIDHandler         endpointModifyHandlerParams
	patchEndpointIDHandler       endpointModifyHandlerParams
	patchEndpointIDLabelsHandler endpointModifyHandlerParams
	patchEndpointIDConfigHandler endpointModifyHandlerParams
)

func newEndpointHandlers(getP endpointGetHandlerParams, postP endpointModifyHandlerParams) endpointHandlersOut {
	return endpointHandlersOut{
		GetEndpointHandler:          getEndpointHandler(getP),
		GetEndpointIDHandler:        getEndpointIDHandler(getP),
		GetEndpointIDConfigHandler:  getEndpointIDConfigHandler(getP),
		GetEndpointIDLabelsHandler:  getEndpointIDLabelsHandler(getP),
		GetEndpointIDLogHandler:     getEndpointIDLogHandler(getP),
		GetEndpointIDHealthzHandler: getEndpointIDHealthzHandler(getP),

		DeleteEndpointIDHandler:      deleteEndpointHandler(postP),
		PutEndpointIDHandler:         putEndpointIDHandler(postP),
		PatchEndpointIDHandler:       patchEndpointIDHandler(postP),
		PatchEndpointIDLabelsHandler: patchEndpointIDLabelsHandler(postP),
		PatchEndpointIDConfigHandler: patchEndpointIDConfigHandler(postP),
	}
}

var errEndpointNotFound = errors.New("endpoint not found")

func (h getEndpointHandler) Handle(params endpointapi.GetEndpointParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointList)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	resEPs := GetEndpointList(h.Endpoints, params.Labels)

	if params.Labels != nil && len(resEPs) == 0 {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointNotFound()
	}

	return endpointapi.NewGetEndpointOK().WithPayload(resEPs)
}

// GetEndpointList retrieves endpoints matching the given (optional) label set. Returns
// endpoint as REST API models.
// Exported for use in cmd.getDebugInfoHandler. Unexport once debuginfo handler moves here.
func GetEndpointList(endpoints endpointLookup, modelLabels models.Labels) []*models.Endpoint {
	maxGoroutines := runtime.NumCPU()
	var (
		epWorkersWg, epsAppendWg sync.WaitGroup
		convertedLabels          labels.Labels
		resEPs                   []*models.Endpoint
	)

	if modelLabels != nil {
		// Convert params.Labels to model that we can compare with the endpoint's labels.
		convertedLabels = labels.NewLabelsFromModel(modelLabels)
	}

	eps := endpoints.GetEndpoints()
	if len(eps) < maxGoroutines {
		maxGoroutines = len(eps)
	}
	epsCh := make(chan *endpoint.Endpoint, maxGoroutines)
	epModelsCh := make(chan *models.Endpoint, maxGoroutines)

	epWorkersWg.Add(maxGoroutines)
	for i := 0; i < maxGoroutines; i++ {
		// Run goroutines to process each endpoint and the corresponding model.
		// The obtained endpoint model is sent to the endpoint models channel from
		// where it will be aggregated later.
		go func(wg *sync.WaitGroup, epModelsChan chan<- *models.Endpoint, epsChan <-chan *endpoint.Endpoint) {
			for ep := range epsChan {
				if ep.HasLabels(convertedLabels) {
					epModelsChan <- ep.GetModel()
				}
			}
			wg.Done()
		}(&epWorkersWg, epModelsCh, epsCh)
	}

	// Send the endpoints to be aggregated a models to the endpoint channel.
	go func(epsChan chan<- *endpoint.Endpoint, eps []*endpoint.Endpoint) {
		for _, ep := range eps {
			epsChan <- ep
		}
		close(epsChan)
	}(epsCh, eps)

	epsAppendWg.Add(1)
	// This needs to be done over channels since we might not receive all
	// the existing endpoints since not all endpoints contain the list of
	// labels that we will use to filter in `ep.HasLabels(convertedLabels)`
	go func(epsAppended *sync.WaitGroup) {
		for ep := range epModelsCh {
			resEPs = append(resEPs, ep)
		}
		epsAppended.Done()
	}(&epsAppendWg)

	epWorkersWg.Wait()
	close(epModelsCh)
	epsAppendWg.Wait()

	return resEPs
}

func (h getEndpointIDHandler) Handle(params endpointapi.GetEndpointIDParams) middleware.Responder {
	h.Log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id} request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.Endpoints.Lookup(params.ID)

	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointIDNotFound()
	} else {
		return endpointapi.NewGetEndpointIDOK().WithPayload(ep.GetModel())
	}
}

func (h getEndpointIDConfigHandler) Handle(params endpointapi.GetEndpointIDConfigParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/config")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.Endpoints.Lookup(params.ID)
	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := ep.GetConfigurationStatus()

		return endpointapi.NewGetEndpointIDConfigOK().WithPayload(cfgStatus)
	}
}

func (h getEndpointIDLabelsHandler) Handle(params endpointapi.GetEndpointIDLabelsParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/labels")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.Endpoints.Lookup(params.ID)
	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointIDLabelsNotFound()
	}

	cfg, err := ep.GetLabelsModel()
	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	}

	return endpointapi.NewGetEndpointIDLabelsOK().WithPayload(cfg)
}

func (h getEndpointIDLogHandler) Handle(params endpointapi.GetEndpointIDLogParams) middleware.Responder {
	h.Log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.Endpoints.Lookup(params.ID)

	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointIDLogNotFound()
	} else {
		return endpointapi.NewGetEndpointIDLogOK().WithPayload(ep.GetStatusModel())
	}
}

func (h getEndpointIDHealthzHandler) Handle(params endpointapi.GetEndpointIDHealthzParams) middleware.Responder {
	h.Log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.Endpoints.Lookup(params.ID)

	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewGetEndpointIDHealthzNotFound()
	} else {
		return endpointapi.NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

func (h deleteEndpointHandler) Handle(params endpointapi.DeleteEndpointIDParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/{id} request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	creator, err := h.EndpointModifierPromise.Await(params.HTTPRequest.Context())
	if err != nil {
		return api.Error(http.StatusServiceUnavailable, err)
	}

	nerr, err := creator.DeleteEndpoint(params.ID)
	if err != nil {
		r.Error(err)
		if apierr, ok := err.(*api.APIError); ok {
			return apierr
		}
		return api.Error(endpointapi.DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return endpointapi.NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	} else {

		return endpointapi.NewDeleteEndpointIDOK()
	}
}

func (h putEndpointIDHandler) Handle(params endpointapi.PutEndpointIDParams) (resp middleware.Responder) {
	epTemplate := params.Endpoint

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointCreate)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	creator, err := h.EndpointModifierPromise.Await(params.HTTPRequest.Context())
	if err != nil {
		return api.Error(http.StatusServiceUnavailable, err)
	}

	code, err := creator.CreateEndpoint(params.HTTPRequest.Context(), epTemplate)
	if err != nil {
		r.Error(err)
		return api.Error(code, err)
	}

	return endpointapi.NewPutEndpointIDCreated()
}

func (h patchEndpointIDHandler) Handle(params endpointapi.PatchEndpointIDParams) middleware.Responder {
	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	epTemplate := params.Endpoint

	creator, err := h.EndpointModifierPromise.Await(params.HTTPRequest.Context())
	if err != nil {
		return api.Error(http.StatusServiceUnavailable, err)
	}

	code, err := creator.PatchEndpoint(params.HTTPRequest.Context(), params.ID, epTemplate)
	if err != nil {
		r.Error(err)
		return api.Error(code, err)
	}

	return endpointapi.NewPatchEndpointIDOK()
}

// modifyEndpointIdentityLabelsFromAPI adds and deletes the given labels on given endpoint ID.
// Performs checks for whether the endpoint may be modified by an API call.
// The received `add` and `del` labels will be filtered with the valid label prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (h patchEndpointIDLabelsHandler) modifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, _ := labelsfilter.Filter(add)
	delLabels, _ := labelsfilter.Filter(del)
	if lbls := addLabels.FindReserved(); lbls != nil {
		return endpointapi.PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls != nil {
		return endpointapi.PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := h.Endpoints.Lookup(id)
	if err != nil {
		return endpointapi.PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return endpointapi.PatchEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return endpointapi.PatchEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(addLabels, delLabels); err != nil {
		return endpointapi.PatchEndpointIDLabelsNotFoundCode, err
	}

	return endpointapi.PatchEndpointIDLabelsOKCode, nil
}

func (h patchEndpointIDLabelsHandler) Handle(params endpointapi.PatchEndpointIDLabelsParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/labels request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	mod := params.Configuration
	lbls := labels.NewLabelsFromModel(mod.User)

	ep, err := h.Endpoints.Lookup(params.ID)
	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound)
		return endpointapi.NewPatchEndpointIDLabelsNotFound()
	}

	add, del, err := ep.ApplyUserLabelChanges(lbls)
	if err != nil {
		r.Error(err)
		return api.Error(endpointapi.PutEndpointIDInvalidCode, err)
	}

	code, err := h.modifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		r.Error(err)
		return api.Error(code, err)
	}
	return endpointapi.NewPatchEndpointIDLabelsOK()
}

func (h patchEndpointIDConfigHandler) Handle(params endpointapi.PatchEndpointIDConfigParams) middleware.Responder {
	h.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/config request")

	r, err := h.RateLimit.Wait(params.HTTPRequest.Context(), APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if err := h.endpointUpdate(params.ID, params.EndpointConfiguration); err != nil {
		r.Error(err)
		if apierr, ok := err.(*api.APIError); ok {
			return apierr
		}
		return api.Error(endpointapi.PatchEndpointIDFailedCode, err)
	}

	return endpointapi.NewPatchEndpointIDConfigOK()
}

// endpointUpdate updates the options of the given endpoint and regenerates the endpoint
func (h patchEndpointIDConfigHandler) endpointUpdate(id string, cfg *models.EndpointConfigurationSpec) error {
	ep, err := h.Endpoints.Lookup(id)
	if err != nil {
		return api.Error(endpointapi.PatchEndpointIDInvalidCode, err)
	} else if ep == nil {
		return api.New(endpointapi.PatchEndpointIDConfigNotFoundCode, "endpoint %s not found", id)
	} else if err := ep.APICanModifyConfig(cfg.Options); err != nil {
		return api.Error(endpointapi.PatchEndpointIDInvalidCode, err)
	}

	if err := ep.Update(cfg); err != nil {
		switch err.(type) {
		case endpoint.UpdateValidationError:
			return api.Error(endpointapi.PatchEndpointIDConfigInvalidCode, err)
		default:
			return api.Error(endpointapi.PatchEndpointIDConfigFailedCode, err)
		}
	}
	if err := h.Endpoints.UpdateReferences(ep); err != nil {
		return api.Error(endpointapi.PatchEndpointIDNotFoundCode, err)
	}

	return nil
}
