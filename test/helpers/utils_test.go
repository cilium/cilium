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

package helpers

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jeffail/gabs"
	. "gopkg.in/check.v1"
)

// k8sVersion should be kept in sync with ``test/test_suite_test.go``.
const k8sVersion = "1.10"

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

// Hook up gocheck into the "go test" runner.
type helpersSuite struct{}

var _ = Suite(&helpersSuite{})

func (h *helpersSuite) TestRemoveLegacyArguments(c *C) {
	var path = filepath.Join("..", "..", "examples", "kubernetes", k8sVersion, "cilium.yaml")
	var result bytes.Buffer

	objects, err := DecodeYAMLOrJSON(path)
	c.Assert(err, IsNil)
	c.Assert(objects, NotNil)

	for _, object := range objects {
		data, err := json.Marshal(object)
		c.Assert(err, IsNil)
		c.Assert(data, NotNil)

		jsonObj, err := gabs.ParseJSON(data)
		c.Assert(err, IsNil)
		c.Assert(jsonObj, NotNil)

		value, _ := jsonObj.Path("kind").Data().(string)
		if value == daemonSet {
			container := jsonObj.Path("spec.template.spec.containers").Index(0)
			c.Assert(container, NotNil)
			err = removeLegacyArguments(container.Path("args"))
			c.Assert(err, IsNil)
		}
		_, err = result.WriteString(jsonObj.String())
		c.Assert(err, IsNil)
	}

	c.Assert(strings.Contains(result.String(), legacyArg), Equals, false)
}
