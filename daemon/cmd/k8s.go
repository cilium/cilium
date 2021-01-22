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
	"bytes"

	. "github.com/cilium/cilium/api/v1/server/restapi/k8s"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2/client"

	"github.com/go-openapi/runtime/middleware"
)

func newPutCRDHandler() *putCRD {
	return &putCRD{}
}

func (h *putCRD) Handle(params PutCrdParams) middleware.Responder {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(params.Crd); err != nil {
		return api.Error(PutCrdFailureCode, err)
	}
	defer params.Crd.Close()

	if err := client.CreateCustomResourceDefinitionFromBytes(
		k8s.APIExtClient(),
		buf.Bytes(),
	); err != nil {
		return api.Error(PutCrdFailureCode, err)
	}

	return NewPutCrdCreated()
}

type putCRD struct{}
