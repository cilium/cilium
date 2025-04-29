// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"fmt"
	"log/slog"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	recorderapi "github.com/cilium/cilium/api/v1/server/restapi/recorder"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type putRecorderIDHandler struct {
	logger   *slog.Logger
	recorder *Recorder
}

func (h *putRecorderIDHandler) Handle(params recorderapi.PutRecorderIDParams) middleware.Responder {
	h.logger.Debug(
		"PUT /recorder/{id} request",
		logfields.Params, params,
	)
	if params.Config.ID == nil {
		return api.Error(recorderapi.PutRecorderIDFailureCode, fmt.Errorf("invalid recorder ID 0"))
	}
	ri, err := ModelToRecorder(params.Config)
	if err != nil {
		return api.Error(recorderapi.PutRecorderIDFailureCode, err)
	}
	created, err := h.recorder.UpsertRecorder(ri)
	if err != nil {
		return api.Error(recorderapi.PutRecorderIDFailureCode, err)
	} else if created {
		return recorderapi.NewPutRecorderIDCreated()
	} else {
		return recorderapi.NewPutRecorderIDOK()
	}
}

type deleteRecorderIDHandler struct {
	logger   *slog.Logger
	recorder *Recorder
}

func (h *deleteRecorderIDHandler) Handle(params recorderapi.DeleteRecorderIDParams) middleware.Responder {
	h.logger.Debug(
		"DELETE /recorder/{id} request",
		logfields.Params, params,
	)
	found, err := h.recorder.DeleteRecorder(ID(params.ID))
	switch {
	case err != nil:
		return api.Error(recorderapi.DeleteRecorderIDFailureCode, err)
	case !found:
		return recorderapi.NewDeleteRecorderIDNotFound()
	default:
		return recorderapi.NewDeleteRecorderIDOK()
	}
}

type getRecorderIDHandler struct {
	logger   *slog.Logger
	recorder *Recorder
}

func (h *getRecorderIDHandler) Handle(params recorderapi.GetRecorderIDParams) middleware.Responder {
	h.logger.Debug(
		"GET /recorder/{id} request",
		logfields.Params, params,
	)
	ri, err := h.recorder.RetrieveRecorder(ID(params.ID))
	if err != nil {
		return recorderapi.NewGetRecorderIDNotFound()
	}
	spec, err := RecorderToModel(ri)
	if err != nil {
		return api.Error(recorderapi.PutRecorderIDFailureCode, err)
	}
	rec := &models.Recorder{
		Spec: spec,
		Status: &models.RecorderStatus{
			Realized: spec,
		},
	}
	return recorderapi.NewGetRecorderIDOK().WithPayload(rec)
}

type getRecorderHandler struct {
	logger   *slog.Logger
	recorder *Recorder
}

func (h *getRecorderHandler) Handle(params recorderapi.GetRecorderParams) middleware.Responder {
	h.logger.Debug(
		"GET /recorder request",
		logfields.Params, params,
	)
	recList := getRecorderList(h.recorder)
	return recorderapi.NewGetRecorderOK().WithPayload(recList)
}

func getRecorderList(rec *Recorder) []*models.Recorder {
	ris := rec.RetrieveRecorderSet()
	recList := make([]*models.Recorder, 0, len(ris))
	for _, ri := range ris {
		spec, _ := RecorderToModel(ri)
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

type getRecorderMasksHandler struct {
	logger   *slog.Logger
	recorder *Recorder
}

func (h *getRecorderMasksHandler) Handle(params recorderapi.GetRecorderMasksParams) middleware.Responder {
	h.logger.Debug(
		"GET /recorder/masks request",
		logfields.Params, params,
	)
	recMaskList := getRecorderMaskList(h.recorder)
	return recorderapi.NewGetRecorderMasksOK().WithPayload(recMaskList)
}

func getRecorderMaskList(rec *Recorder) []*models.RecorderMask {
	rms := rec.RetrieveRecorderMaskSet()
	recMaskList := make([]*models.RecorderMask, 0, len(rms))
	for _, rm := range rms {
		spec := RecorderMaskToModel(rm)
		recMask := &models.RecorderMask{
			Status: &models.RecorderMaskStatus{
				Realized: spec,
			},
		}
		recMaskList = append(recMaskList, recMask)
	}
	return recMaskList
}
