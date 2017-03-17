// Copyright 2016-2017 Authors of Cilium
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

package apierror

import (
	"fmt"
	"net/http"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/go-openapi/runtime"
)

type ApiError struct {
	code int
	msg  string
}

func New(code int, msg string, args ...interface{}) *ApiError {
	if code <= 0 {
		code = 500
	}

	if len(args) > 0 {
		return &ApiError{code: code, msg: fmt.Sprintf(msg, args...)}
	}
	return &ApiError{code: code, msg: msg}
}

func Error(code int, err error) *ApiError {
	if err == nil {
		err = fmt.Errorf("Error pointer was nil")
	}

	return New(code, err.Error())
}

func (a *ApiError) Error() string {
	return a.msg
}

func (a *ApiError) GetModel() *models.Error {
	m := models.Error(a.msg)
	return &m
}

func (a *ApiError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(a.code)
	m := a.GetModel()
	if err := producer.Produce(rw, m); err != nil {
		panic(err)
	}

}
