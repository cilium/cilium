// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
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

// GetCode returns the code for the API Error.
func (a *APIError) GetCode() int {
	return a.code
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
