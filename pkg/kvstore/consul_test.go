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

package kvstore

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	consulAPI "github.com/hashicorp/consul/api"
)

var handler http.HandlerFunc

func TestMain(m *testing.M) {
	mux := http.NewServeMux()
	// path is hardcoded in consul
	mux.HandleFunc("/v1/status/leader", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	})

	srv := &http.Server{
		Addr:    ":8000",
		Handler: mux,
	}

	go srv.ListenAndServe()

	os.Exit(m.Run())
}

func TestConsulClientRetry(t *testing.T) {
	maxRetries = 3
	retrySleep = time.Second
	tries := 0
	doneC := make(chan struct{})

	handler = func(w http.ResponseWriter, r *http.Request) {
		if tries++; tries+1 == maxRetries {
			close(doneC)
		}

		http.Error(w, "retry test error", http.StatusInternalServerError)
	}

	_, err := newConsulClient(&consulAPI.Config{
		Address: ":8000",
	})

	select {
	case <-doneC:
	case <-time.After(time.Second * 5):
		t.Log("timeout")
		t.FailNow()
	}

	// we should get a failure
	if err == nil {
		t.Log("no error")
		t.FailNow()
	}
}

func TestConsulClientOk(t *testing.T) {
	maxRetries = 3
	doneC := make(chan struct{})

	handler = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "\"nanananananananananleaaderrrr\"")
		close(doneC)
	}

	_, err := newConsulClient(&consulAPI.Config{
		Address: ":8000",
	})

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
