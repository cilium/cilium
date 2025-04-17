// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/daemon/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var errEndpointNotFound = errors.New("endpoint not found")

func getEndpointHandler(d *Daemon, params GetEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointList)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	resEPs := d.endpointManager.GetEndpointList(params)

	if params.Labels != nil && len(resEPs) == 0 {
		r.Error(errEndpointNotFound, GetEndpointNotFoundCode)
		return NewGetEndpointNotFound()
	}

	return NewGetEndpointOK().WithPayload(resEPs)
}

func deleteEndpointHandler(d *Daemon, params DeleteEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/ request")

	if params.Endpoint.ContainerID == "" {
		return api.New(DeleteEndpointInvalidCode, "invalid container id")
	}

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if eps := d.endpointManager.GetEndpointsByContainerID(params.Endpoint.ContainerID); len(eps) == 0 {
		return api.New(DeleteEndpointNotFoundCode, "endpoints not found")
	}

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := d.endpointAPIManager.DeleteEndpointByContainerID(params.Endpoint.ContainerID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, DeleteEndpointInvalidCode)
		return api.Error(DeleteEndpointInvalidCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointErrors().WithPayload(int64(nerr))
	}

	return NewDeleteEndpointOK()
}

func getEndpointIDHandler(d *Daemon, params GetEndpointIDParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id} request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDNotFoundCode)
		return NewGetEndpointIDNotFound()
	} else {
		return NewGetEndpointIDOK().WithPayload(ep.GetModel())
	}
}

// handleOutdatedPodInformerRetryPeriod allows to configure the retry period for
// testing purposes.
var handleOutdatedPodInformerRetryPeriod = 100 * time.Millisecond

func putEndpointIDHandler(d *Daemon, params PutEndpointIDParams) (resp middleware.Responder) {
	if ep := params.Endpoint; ep != nil {
		log.WithField("endpoint", logfields.Repr(*ep)).Debug("PUT /endpoint/{id} request")
	} else {
		log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")
	}
	epTemplate := params.Endpoint

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointCreate)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, code, err := d.endpointAPIManager.CreateEndpoint(params.HTTPRequest.Context(), epTemplate)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}

	ep.Logger(daemonSubsys).Info("Successful endpoint creation")

	return NewPutEndpointIDCreated().WithPayload(ep.GetModel())
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

func patchEndpointIDHandler(d *Daemon, params PatchEndpointIDParams) middleware.Responder {
	scopedLog := log.WithField(logfields.Params, logfields.Repr(params))
	if ep := params.Endpoint; ep != nil {
		scopedLog = scopedLog.WithField("endpoint", logfields.Repr(*ep))
	}
	scopedLog.Debug("PATCH /endpoint/{id} request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
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
	newEp, err2 := d.endpointCreator.NewEndpointFromChangeModel(d.ctx, epTemplate)
	if err2 != nil {
		r.Error(err2, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err2)
	}

	var validStateTransition bool

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", *epTemplate.State)
	} else {
		validStateTransition = true
	}

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, PatchEndpointIDNotFoundCode)
		return NewPatchEndpointIDNotFound()
	}
	if err = endpoint.APICanModify(ep); err != nil {
		r.Error(err, PatchEndpointIDInvalidCode)
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?
	reason, err := ep.ProcessChangeRequest(newEp, validStateTransition)
	if err != nil {
		r.Error(err, PatchEndpointIDNotFoundCode)
		return NewPatchEndpointIDNotFound()
	}

	if reason != "" {
		regenMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            reason,
			RegenerationLevel: regeneration.RegenerateWithDatapath,
		}
		if !<-ep.Regenerate(regenMetadata) {
			err := api.Error(PatchEndpointIDFailedCode,
				fmt.Errorf("error while regenerating endpoint."+
					" For more info run: 'cilium endpoint get %d'", ep.ID))
			r.Error(err, PatchEndpointIDFailedCode)
			return err
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	return NewPatchEndpointIDOK()
}

func deleteEndpointIDHandler(d *Daemon, params DeleteEndpointIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/{id} request")

	// Bypass the rate limiter for endpoints that have already been deleted.
	// Kubelet will generate at minimum 2 delete requests for a Pod, so this
	// returns in earlier retruns for over half of all delete calls.
	if ep, err := d.endpointManager.Lookup(params.ID); err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDNotFound()
	}

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointDelete)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if nerr, err := d.endpointAPIManager.DeleteEndpoint(params.ID); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, DeleteEndpointIDErrorsCode)
		return api.Error(DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	}

	return NewDeleteEndpointIDOK()
}

func patchEndpointIDConfigHandler(d *Daemon, params PatchEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/config request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	if err := d.endpointAPIManager.EndpointUpdate(params.ID, params.EndpointConfiguration); err != nil {
		apierr := &api.APIError{}
		if errors.As(err, &apierr) {
			r.Error(err, apierr.GetCode())
			return apierr
		}
		r.Error(err, PatchEndpointIDFailedCode)
		return api.Error(PatchEndpointIDFailedCode, err)
	}

	return NewPatchEndpointIDConfigOK()
}

func getEndpointIDConfigHandler(d *Daemon, params GetEndpointIDConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/config")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDConfigNotFoundCode)
		return NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := ep.GetConfigurationStatus()

		return NewGetEndpointIDConfigOK().WithPayload(cfgStatus)
	}
}

func getEndpointIDLabelsHandler(d *Daemon, params GetEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/labels")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDLabelsNotFoundCode)
		return NewGetEndpointIDLabelsNotFound()
	}

	cfg, err := ep.GetLabelsModel()
	if err != nil {
		r.Error(err, GetEndpointIDInvalidCode)
		return api.Error(GetEndpointIDInvalidCode, err)
	}

	return NewGetEndpointIDLabelsOK().WithPayload(cfg)
}

func getEndpointIDLogHandler(d *Daemon, params GetEndpointIDLogParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDLogInvalidCode)
		return api.Error(GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDLogNotFoundCode)
		return NewGetEndpointIDLogNotFound()
	} else {
		return NewGetEndpointIDLogOK().WithPayload(ep.GetStatusModel())
	}
}

func getEndpointIDHealthzHandler(d *Daemon, params GetEndpointIDHealthzParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointGet)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	ep, err := d.endpointManager.Lookup(params.ID)

	if err != nil {
		r.Error(err, GetEndpointIDHealthzInvalidCode)
		return api.Error(GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, GetEndpointIDHealthzNotFoundCode)
		return NewGetEndpointIDHealthzNotFound()
	} else {
		return NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

func putEndpointIDLabelsHandler(d *Daemon, params PatchEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/labels request")

	r, err := d.apiLimiterSet.Wait(params.HTTPRequest.Context(), restapi.APIRequestEndpointPatch)
	if err != nil {
		return api.Error(http.StatusTooManyRequests, err)
	}
	defer r.Done()

	mod := params.Configuration
	lbls := labels.NewLabelsFromModel(mod.User)

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		r.Error(err, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		r.Error(errEndpointNotFound, PatchEndpointIDLabelsNotFoundCode)
		return NewPatchEndpointIDLabelsNotFound()
	}

	add, del, err := ep.ApplyUserLabelChanges(lbls)
	if err != nil {
		r.Error(err, PutEndpointIDInvalidCode)
		return api.Error(PutEndpointIDInvalidCode, err)
	}

	code, err := d.endpointAPIManager.ModifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		r.Error(err, code)
		return api.Error(code, err)
	}
	return NewPatchEndpointIDLabelsOK()
}
