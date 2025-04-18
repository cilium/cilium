// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	endpointapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
)

var errEndpointNotFound = errors.New("endpoint not found")

type EndpointGetEndpointHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointDeleteEndpointHandler struct {
	apiLimiterSet      *rate.APILimiterSet
	endpointManager    endpointmanager.EndpointManager
	endpointAPIManager EndpointAPIManager
}

type EndpointGetEndpointIDHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointPutEndpointIDHandler struct {
	apiLimiterSet      *rate.APILimiterSet
	endpointAPIManager EndpointAPIManager
}

type EndpointPatchEndpointIDHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
	endpointCreator endpointcreator.EndpointCreator
}

type EndpointDeleteEndpointIDHandler struct {
	apiLimiterSet      *rate.APILimiterSet
	endpointManager    endpointmanager.EndpointManager
	endpointAPIManager EndpointAPIManager
}

type EndpointPatchEndpointIDConfigHandler struct {
	apiLimiterSet      *rate.APILimiterSet
	endpointAPIManager EndpointAPIManager
}

type EndpointGetEndpointIDConfigHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointGetEndpointIDLabelsHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointGetEndpointIDLogHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointGetEndpointIDHealthzHandler struct {
	apiLimiterSet   *rate.APILimiterSet
	endpointManager endpointmanager.EndpointManager
}

type EndpointPatchEndpointIDLabelsHandler struct {
	apiLimiterSet      *rate.APILimiterSet
	endpointManager    endpointmanager.EndpointManager
	endpointAPIManager EndpointAPIManager
}

func (h *EndpointGetEndpointHandler) Handle(params endpointapi.GetEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointList)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	resEPs := h.endpointManager.GetEndpointList(params)

	if params.Labels != nil && len(resEPs) == 0 {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointNotFoundCode)
		return endpointapi.NewGetEndpointNotFound()
	}

	return endpointapi.NewGetEndpointOK().WithPayload(resEPs)
}

func (h *EndpointDeleteEndpointHandler) Handle(params endpointapi.DeleteEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/ request")

	if params.Endpoint.ContainerID == "" {
		return api.New(endpointapi.DeleteEndpointInvalidCode, "invalid container id")
	}

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if eps := h.endpointManager.GetEndpointsByContainerID(params.Endpoint.ContainerID); len(eps) == 0 {
		return api.New(endpointapi.DeleteEndpointNotFoundCode, "endpoints not found")
	}

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := h.endpointAPIManager.DeleteEndpointByContainerID(params.Endpoint.ContainerID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, endpointapi.DeleteEndpointInvalidCode)
		return api.Error(endpointapi.DeleteEndpointInvalidCode, err)
	} else if nerr > 0 {
		return endpointapi.NewDeleteEndpointErrors().WithPayload(int64(nerr))
	}

	return endpointapi.NewDeleteEndpointOK()
}

func (h *EndpointGetEndpointIDHandler) Handle(params endpointapi.GetEndpointIDParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id} request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDInvalidCode)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointIDNotFoundCode)
		return endpointapi.NewGetEndpointIDNotFound()
	} else {
		return endpointapi.NewGetEndpointIDOK().WithPayload(ep.GetModel())
	}
}

func (h *EndpointPutEndpointIDHandler) Handle(params endpointapi.PutEndpointIDParams) (resp middleware.Responder) {
	if ep := params.Endpoint; ep != nil {
		log.WithField("endpoint", logfields.Repr(*ep)).Debug("PUT /endpoint/{id} request")
	} else {
		log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")
	}
	epTemplate := params.Endpoint

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointCreate)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, code, err := h.endpointAPIManager.CreateEndpoint(params.HTTPRequest.Context(), epTemplate)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}

	ep.Logger(daemonSubsys).Info("Successful endpoint creation")

	return endpointapi.NewPutEndpointIDCreated().WithPayload(ep.GetModel())
}

// validPatchTransitionState checks whether the state to which the provided
// model specifies is one to which an Endpoint can transition as part of a
// call to PATCH on an Endpoint.
func validPatchTransitionState(state *models.EndpointState) bool {
	if state != nil {
		switch endpoint.State(*state) {
		case "", endpoint.StateWaitingForIdentity, endpoint.StateReady:
			return true
		}
	}
	return false
}

func (h *EndpointPatchEndpointIDHandler) Handle(params endpointapi.PatchEndpointIDParams) middleware.Responder {
	scopedLog := log.WithField(logfields.Params, logfields.Repr(params))
	if ep := params.Endpoint; ep != nil {
		scopedLog = scopedLog.WithField("endpoint", logfields.Repr(*ep))
	}
	scopedLog.Debug("PATCH /endpoint/{id} request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	epTemplate := params.Endpoint

	log.WithFields(logrus.Fields{
		logfields.EndpointID:         params.ID,
		"addressing":                 epTemplate.Addressing,
		logfields.ContainerID:        epTemplate.ContainerID,
		logfields.ContainerInterface: epTemplate.ContainerInterfaceName,
		"datapathConfiguration":      epTemplate.DatapathConfiguration,
		logfields.Interface:          epTemplate.InterfaceName,
		logfields.K8sPodName:         epTemplate.K8sNamespace + "/" + epTemplate.K8sPodName,
		logfields.Labels:             epTemplate.Labels,
	}).Info("Patch endpoint request")

	// Validate the template. Assignment afterwards is atomic.
	// Note: newEp's labels are ignored.
	newEp, err2 := h.endpointCreator.NewEndpointFromChangeModel(params.HTTPRequest.Context(), epTemplate)
	if err2 != nil {
		r.Error(err2, endpointapi.PutEndpointIDInvalidCode)
		return api.Error(endpointapi.PutEndpointIDInvalidCode, err2)
	}

	var validStateTransition bool

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", *epTemplate.State)
	} else {
		validStateTransition = true
	}

	ep, err := h.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDInvalidCode)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.PatchEndpointIDNotFoundCode)
		return endpointapi.NewPatchEndpointIDNotFound()
	}
	if err = endpoint.APICanModify(ep); err != nil {
		r.Error(err, endpointapi.PatchEndpointIDInvalidCode)
		return api.Error(endpointapi.PatchEndpointIDInvalidCode, err)
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?
	reason, err := ep.ProcessChangeRequest(newEp, validStateTransition)
	if err != nil {
		r.Error(err, endpointapi.PatchEndpointIDNotFoundCode)
		return endpointapi.NewPatchEndpointIDNotFound()
	}

	if reason != "" {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            reason,
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}
		if !<-ep.Regenerate(regenMetadata) {
			err := api.Error(endpointapi.PatchEndpointIDFailedCode,
				fmt.Errorf("error while regenerating endpoint."+
					" For more info run: 'cilium endpoint get %d'", ep.ID))
			r.Error(err, endpointapi.PatchEndpointIDFailedCode)
			return err
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	return endpointapi.NewPatchEndpointIDOK()
}

func (h *EndpointDeleteEndpointIDHandler) Handle(params endpointapi.DeleteEndpointIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/{id} request")

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if ep, err := h.endpointManager.Lookup(params.ID); err != nil {
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		return endpointapi.NewGetEndpointIDNotFound()
	}

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := h.endpointAPIManager.DeleteEndpoint(params.ID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, endpointapi.DeleteEndpointIDErrorsCode)
		return api.Error(endpointapi.DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return endpointapi.NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	}

	return endpointapi.NewDeleteEndpointIDOK()
}

func (h *EndpointPatchEndpointIDConfigHandler) Handle(params endpointapi.PatchEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/config request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if err := h.endpointAPIManager.EndpointUpdate(params.ID, params.EndpointConfiguration); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, endpointapi.PatchEndpointIDFailedCode)
		return api.Error(endpointapi.PatchEndpointIDFailedCode, err)
	}

	return endpointapi.NewPatchEndpointIDConfigOK()
}

func (h *EndpointGetEndpointIDConfigHandler) Handle(params endpointapi.GetEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/config")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDInvalidCode)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointIDConfigNotFoundCode)
		return endpointapi.NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := ep.GetConfigurationStatus()

		return endpointapi.NewGetEndpointIDConfigOK().WithPayload(cfgStatus)
	}
}

func (h *EndpointGetEndpointIDLabelsHandler) Handle(params endpointapi.GetEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/labels")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDInvalidCode)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointIDLabelsNotFoundCode)
		return endpointapi.NewGetEndpointIDLabelsNotFound()
	}

	cfg, err := ep.GetLabelsModel()
	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDInvalidCode)
		return api.Error(endpointapi.GetEndpointIDInvalidCode, err)
	}

	return endpointapi.NewGetEndpointIDLabelsOK().WithPayload(cfg)
}

func (h *EndpointGetEndpointIDLogHandler) Handle(params endpointapi.GetEndpointIDLogParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDLogInvalidCode)
		return api.Error(endpointapi.GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointIDLogNotFoundCode)
		return endpointapi.NewGetEndpointIDLogNotFound()
	} else {
		return endpointapi.NewGetEndpointIDLogOK().WithPayload(ep.GetStatusModel())
	}
}

func (h *EndpointGetEndpointIDHealthzHandler) Handle(params endpointapi.GetEndpointIDHealthzParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := h.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, endpointapi.GetEndpointIDHealthzInvalidCode)
		return api.Error(endpointapi.GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.GetEndpointIDHealthzNotFoundCode)
		return endpointapi.NewGetEndpointIDHealthzNotFound()
	} else {
		return endpointapi.NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

func (h *EndpointPatchEndpointIDLabelsHandler) Handle(params endpointapi.PatchEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/labels request")

	r, err := h.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	mod := params.Configuration
	lbls := labels.NewLabelsFromModel(mod.User)

	ep, err := h.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, endpointapi.PutEndpointIDInvalidCode)
		return api.Error(endpointapi.PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, endpointapi.PatchEndpointIDLabelsNotFoundCode)
		return endpointapi.NewPatchEndpointIDLabelsNotFound()
	}

	add, del, err := ep.ApplyUserLabelChanges(lbls)
	if err != nil {
		r.Error(err, endpointapi.PutEndpointIDInvalidCode)
		return api.Error(endpointapi.PutEndpointIDInvalidCode, err)
	}

	code, err := h.endpointAPIManager.ModifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}
	return endpointapi.NewPatchEndpointIDLabelsOK()
}
