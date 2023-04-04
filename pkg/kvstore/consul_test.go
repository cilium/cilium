// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build integration_tests

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
	Client().Close(context.TODO())
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
