// Copyright 2021 Authors of Cilium
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

package cmd

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/recorder"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/recorder"

	"github.com/go-openapi/runtime/middleware"
)

type putRecorderID struct {
	rec *recorder.Recorder
}

func NewPutRecorderIDHandler(rec *recorder.Recorder) PutRecorderIDHandler {
	return &putRecorderID{rec: rec}
}

func (h *putRecorderID) Handle(params PutRecorderIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /recorder/{id} request")
	if params.Config.ID == nil {
		return api.Error(PutRecorderIDFailureCode, fmt.Errorf("invalid recorder ID 0"))
	}
	ri, err := recorder.ModelToRecorder(params.Config)
	if err != nil {
		return api.Error(PutRecorderIDFailureCode, err)
	}
	created, err := h.rec.UpsertRecorder(ri)
	if err != nil {
		return api.Error(PutRecorderIDFailureCode, err)
	} else if created {
		return NewPutRecorderIDCreated()
	} else {
		return NewPutRecorderIDOK()
	}
}

type deleteRecorderID struct {
	rec *recorder.Recorder
}

func NewDeleteRecorderIDHandler(rec *recorder.Recorder) DeleteRecorderIDHandler {
	return &deleteRecorderID{rec: rec}
}

func (h *deleteRecorderID) Handle(params DeleteRecorderIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /recorder/{id} request")
	found, err := h.rec.DeleteRecorder(recorder.ID(params.ID))
	switch {
	case err != nil:
		return api.Error(DeleteRecorderIDFailureCode, err)
	case !found:
		return NewDeleteRecorderIDNotFound()
	default:
		return NewDeleteRecorderIDOK()
	}
}

type getRecorderID struct {
	rec *recorder.Recorder
}

func NewGetRecorderIDHandler(rec *recorder.Recorder) GetRecorderIDHandler {
	return &getRecorderID{rec: rec}
}

func (h *getRecorderID) Handle(params GetRecorderIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /recorder/{id} request")
	ri, err := h.rec.RetrieveRecorder(recorder.ID(params.ID))
	if err != nil {
		return NewGetRecorderIDNotFound()
	}
	spec, err := recorder.RecorderToModel(ri)
	if err != nil {
		return api.Error(PutRecorderIDFailureCode, err)
	}
	rec := &models.Recorder{
		Spec: spec,
		Status: &models.RecorderStatus{
			Realized: spec,
		},
	}
	return NewGetRecorderIDOK().WithPayload(rec)
}

type getRecorder struct {
	rec *recorder.Recorder
}

func NewGetRecorderHandler(rec *recorder.Recorder) GetRecorderHandler {
	return &getRecorder{rec: rec}
}

func (h *getRecorder) Handle(params GetRecorderParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /recorder request")
	recList := getRecorderList(h.rec)
	return NewGetRecorderOK().WithPayload(recList)
}

func getRecorderList(rec *recorder.Recorder) []*models.Recorder {
	ris := rec.RetrieveRecorderSet()
	recList := make([]*models.Recorder, 0, len(ris))
	for _, ri := range ris {
		spec, _ := recorder.RecorderToModel(ri)
		rec := &models.Recorder{
			Spec: spec,
			Status: &models.RecorderStatus{
				Realized: spec,
			},
		}
		recList = append(recList, rec)
	}
	return recList
}

type getRecorderMasks struct {
	rec *recorder.Recorder
}

func NewGetRecorderMasksHandler(rec *recorder.Recorder) GetRecorderMasksHandler {
	return &getRecorderMasks{rec: rec}
}

func (h *getRecorderMasks) Handle(params GetRecorderMasksParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /recorder/masks request")
	recMaskList := getRecorderMaskList(h.rec)
	return NewGetRecorderMasksOK().WithPayload(recMaskList)
}

func getRecorderMaskList(rec *recorder.Recorder) []*models.RecorderMask {
	rms := rec.RetrieveRecorderMaskSet()
	recMaskList := make([]*models.RecorderMask, 0, len(rms))
	for _, rm := range rms {
		spec := recorder.RecorderMaskToModel(rm)
		recMask := &models.RecorderMask{
			Status: &models.RecorderMaskStatus{
				Realized: spec,
			},
		}
		recMaskList = append(recMaskList, recMask)
	}
	return recMaskList
}
