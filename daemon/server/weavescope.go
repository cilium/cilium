//
// Copyright 2016 Authors of Cilium
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
//
package server

import (
	"bufio"
	"bytes"
	"net/http"

	"github.com/ugorji/go/codec"
)

func (router *Router) weaveScopeReport(w http.ResponseWriter, r *http.Request) {
	report, err := router.daemon.WeaveScopeReport()
	if err != nil {
		processServerError(w, r, err)
		return
	}

	log.Debugf("weaveScopeReport reply: %+v", report)
	var b bytes.Buffer
	foo := bufio.NewWriter(&b)
	err = codec.NewEncoder(foo, &codec.MsgpackHandle{}).Encode(report)
	foo.Flush()
	log.Debugf("weaveScopeReport Bytes: %s, %s", err, b.String())

	w.WriteHeader(http.StatusOK)
	if err := codec.NewEncoder(w, &codec.MsgpackHandle{}).Encode(report); err != nil {
		processServerError(w, r, err)
		return
	}
}
