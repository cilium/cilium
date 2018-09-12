// Copyright 2018 Authors of Cilium
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

package test

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

var Tmpdir string

func init() {
	var err error
	Tmpdir, err = ioutil.TempDir("", "cilium_envoy_go_test")
	if err != nil {
		log.Fatal("Failed to create a temporaty directory for testing")
	}
}
