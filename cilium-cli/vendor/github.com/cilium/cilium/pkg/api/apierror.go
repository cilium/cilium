// Copyright 2016-2018 Authors of Cilium
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

package api

import (
	"fmt"
	"net/http"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/go-openapi/runtime"
)

// APIError is the error representation for the API.
type APIError struct {
	code int
	msg  string
}

// New creates a API error from the code, msg and extra arguments.
func New(code int, msg string, args ...interface{}) *APIError {
	if code <= 0 {
		code = 500
	}

	if len(args) > 0 {
		return &APIError{code: code, msg: fmt.Sprintf(msg, args...)}
	}
	return &APIError{code: code, msg: msg}
}

// Error creates a new API error from the code and error.
func Error(code int, err error) *APIError {
	if err == nil {
		err = fmt.Errorf("Error pointer was nil")
	}

	return New(code, err.Error())
}

// Error returns the API error message.
func (a *APIError) Error() string {
	return a.msg
}

// GetModel returns model error.
func (a *APIError) GetModel() *models.Error {
	m := models.Error(a.msg)
	return &m
}

// WriteResponse to the client.
func (a *APIError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(a.code)
	m := a.GetModel()
	if err := producer.Produce(rw, m); err != nil {
		panic(err)
	}

}
