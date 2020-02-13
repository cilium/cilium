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

// +build !privileged_tests

package kvstore

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	consulAPI "github.com/hashicorp/consul/api"
	. "gopkg.in/check.v1"
)

type ConsulSuite struct {
	BaseTests
}

var _ = Suite(&ConsulSuite{})

func (e *ConsulSuite) SetUpTest(c *C) {
	SetupDummy("consul")
}

func (e *ConsulSuite) TearDownTest(c *C) {
	Client().Close()
}

var handler http.HandlerFunc

func TestMain(m *testing.M) {
	mux := http.NewServeMux()
	// path is hardcoded in consul
	mux.HandleFunc("/v1/status/leader", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	})

	mux.HandleFunc("/v1/session/create", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "{ \"ID\": \"adf4238a-882b-9ddc-4a9d-5b6758e4159e\"}")
	})

	// /v1/session/renew/{uuid} does not need to be handled for the basic
	// test to succeed

	srv := &http.Server{
		Addr:    ":8000",
		Handler: mux,
	}

	go srv.ListenAndServe()

	os.Exit(m.Run())
}

func TestConsulClientOk(t *testing.T) {
	maxRetries = 3
	doneC := make(chan struct{})

	handler = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "\"nanananananananananleaaderrrr\"")
		close(doneC)
	}

	_, err := newConsulClient(context.TODO(), &consulAPI.Config{
		Address: ":8000",
	}, nil)

	select {
	case <-doneC:
	case <-time.After(time.Second * 5):
		t.Log("timeout")
		t.FailNow()
	}

	// we should not get a failure
	if err != nil {
		t.Log("error:" + err.Error())
		t.FailNow()
	}
}
