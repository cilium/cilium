/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package websocket

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestAuthenticateRequest(t *testing.T) {
	auth := NewProtocolAuthenticator(authenticator.TokenFunc(func(token string) (user.Info, bool, error) {
		if token != "token" {
			t.Errorf("unexpected token: %s", token)
		}
		return &user.DefaultInfo{Name: "user"}, true, nil
	}))
	user, ok, err := auth.AuthenticateRequest(&http.Request{
		Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
	})
	if !ok || user == nil || err != nil {
		t.Errorf("expected valid user")
	}
}

func TestAuthenticateRequestTokenInvalid(t *testing.T) {
	auth := NewProtocolAuthenticator(authenticator.TokenFunc(func(token string) (user.Info, bool, error) {
		return nil, false, nil
	}))
	user, ok, err := auth.AuthenticateRequest(&http.Request{
		Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
	})
	if ok || user != nil {
		t.Errorf("expected not authenticated user")
	}
	if err != errInvalidToken {
		t.Errorf("expected errInvalidToken error, got %v", err)
	}
}

func TestAuthenticateRequestTokenInvalidCustomError(t *testing.T) {
	customError := errors.New("custom")
	auth := NewProtocolAuthenticator(authenticator.TokenFunc(func(token string) (user.Info, bool, error) {
		return nil, false, customError
	}))
	user, ok, err := auth.AuthenticateRequest(&http.Request{
		Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
	})
	if ok || user != nil {
		t.Errorf("expected not authenticated user")
	}
	if err != customError {
		t.Errorf("expected custom error, got %v", err)
	}
}

func TestAuthenticateRequestTokenError(t *testing.T) {
	auth := NewProtocolAuthenticator(authenticator.TokenFunc(func(token string) (user.Info, bool, error) {
		return nil, false, errors.New("error")
	}))
	user, ok, err := auth.AuthenticateRequest(&http.Request{
		Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
	})
	if ok || user != nil || err == nil {
		t.Errorf("expected error")
	}
}

func TestAuthenticateRequestBadValue(t *testing.T) {
	testCases := []struct {
		Req *http.Request
	}{
		{Req: &http.Request{}},
		{Req: &http.Request{Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"other-protocol"}}},
		},
		{Req: &http.Request{Header: http.Header{
			"Connection":             []string{"upgrade"},
			"Upgrade":                []string{"websocket"},
			"Sec-Websocket-Protocol": []string{"base64url.bearer.authorization.k8s.io."}}},
		},
	}
	for i, testCase := range testCases {
		auth := NewProtocolAuthenticator(authenticator.TokenFunc(func(token string) (user.Info, bool, error) {
			t.Errorf("authentication should not have been called")
			return nil, false, nil
		}))
		user, ok, err := auth.AuthenticateRequest(testCase.Req)
		if ok || user != nil || err != nil {
			t.Errorf("%d: expected not authenticated (no token)", i)
		}
	}
}

func TestBearerToken(t *testing.T) {
	tests := map[string]struct {
		ProtocolHeaders []string
		TokenAuth       authenticator.Token

		ExpectedUserName        string
		ExpectedOK              bool
		ExpectedErr             bool
		ExpectedProtocolHeaders []string
	}{
		"no header": {
			ProtocolHeaders:         nil,
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             false,
			ExpectedProtocolHeaders: nil,
		},
		"empty header": {
			ProtocolHeaders:         []string{""},
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             false,
			ExpectedProtocolHeaders: []string{""},
		},
		"non-bearer header": {
			ProtocolHeaders:         []string{"undefined"},
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             false,
			ExpectedProtocolHeaders: []string{"undefined"},
		},
		"empty bearer token": {
			ProtocolHeaders:         []string{"base64url.bearer.authorization.k8s.io."},
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             false,
			ExpectedProtocolHeaders: []string{"base64url.bearer.authorization.k8s.io."},
		},
		"valid bearer token removing header": {
			ProtocolHeaders:         []string{"base64url.bearer.authorization.k8s.io.dG9rZW4", "dummy, dummy2"},
			TokenAuth:               authenticator.TokenFunc(func(t string) (user.Info, bool, error) { return &user.DefaultInfo{Name: "myuser"}, true, nil }),
			ExpectedUserName:        "myuser",
			ExpectedOK:              true,
			ExpectedErr:             false,
			ExpectedProtocolHeaders: []string{"dummy,dummy2"},
		},
		"invalid bearer token": {
			ProtocolHeaders:         []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
			TokenAuth:               authenticator.TokenFunc(func(t string) (user.Info, bool, error) { return nil, false, nil }),
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             true,
			ExpectedProtocolHeaders: []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
		"error bearer token": {
			ProtocolHeaders:         []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
			TokenAuth:               authenticator.TokenFunc(func(t string) (user.Info, bool, error) { return nil, false, errors.New("error") }),
			ExpectedUserName:        "",
			ExpectedOK:              false,
			ExpectedErr:             true,
			ExpectedProtocolHeaders: []string{"base64url.bearer.authorization.k8s.io.dG9rZW4,dummy"},
		},
	}

	for k, tc := range tests {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Connection", "upgrade")
		req.Header.Set("Upgrade", "websocket")
		for _, h := range tc.ProtocolHeaders {
			req.Header.Add("Sec-Websocket-Protocol", h)
		}

		bearerAuth := NewProtocolAuthenticator(tc.TokenAuth)
		u, ok, err := bearerAuth.AuthenticateRequest(req)
		if tc.ExpectedErr != (err != nil) {
			t.Errorf("%s: Expected err=%v, got %v", k, tc.ExpectedErr, err)
			continue
		}
		if ok != tc.ExpectedOK {
			t.Errorf("%s: Expected ok=%v, got %v", k, tc.ExpectedOK, ok)
			continue
		}
		if ok && u.GetName() != tc.ExpectedUserName {
			t.Errorf("%s: Expected username=%v, got %v", k, tc.ExpectedUserName, u.GetName())
			continue
		}
		if !reflect.DeepEqual(req.Header["Sec-Websocket-Protocol"], tc.ExpectedProtocolHeaders) {
			t.Errorf("%s: Expected headers=%#v, got %#v", k, tc.ExpectedProtocolHeaders, req.Header["Sec-Websocket-Protocol"])
			continue
		}
	}
}
