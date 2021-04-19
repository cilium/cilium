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

	return api.Error(PutRecorderIDFailureCode, fmt.Errorf("not supported yet"))
}

type deleteRecorderID struct {
	rec *recorder.Recorder
}

func NewDeleteRecorderIDHandler(rec *recorder.Recorder) DeleteRecorderIDHandler {
	return &deleteRecorderID{rec: rec}
}

func (h *deleteRecorderID) Handle(params DeleteRecorderIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /recorder/{id} request")
	return NewDeleteRecorderIDNotFound()
}

type getRecorderID struct {
	rec *recorder.Recorder
}

func NewGetRecorderIDHandler(rec *recorder.Recorder) GetRecorderIDHandler {
	return &getRecorderID{rec: rec}
}

func (h *getRecorderID) Handle(params GetRecorderIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /recorder/{id} request")
	return NewGetRecorderIDNotFound()
}

type getRecorder struct {
	rec *recorder.Recorder
}

func NewGetRecorderHandler(rec *recorder.Recorder) GetRecorderHandler {
	return &getRecorder{rec: rec}
}

func (h *getRecorder) Handle(params GetRecorderParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /recorder request")
	return NewGetRecorderOK()
}
