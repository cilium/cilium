// Copyright 2017 Authors of Cilium
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
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"
)

var manifestBase = "k8sT/manifests"

type ManifestValues struct {
	Index int
}

// GenerateManifestForEndpoints generates k8s manifests that will create
// endpointCount cilium endpoints when applied.
// 1/3 of endpoints is going to be servers, the rest clients.
func GenerateManifestForEndpoints(endpointCount int, manifestPath string) (string, error) {
	serverTemplateStr, err := ioutil.ReadFile(path.Join(manifestBase, "server.yaml"))
	if err != nil {
		return "", err
	}
	serverTemplate, err := template.New("server").Parse(string(serverTemplateStr))
	if err != nil {
		return "", err
	}

	clientTemplateStr, err := ioutil.ReadFile(path.Join(manifestBase, "client.yaml"))
	if err != nil {
		return "", err
	}
	clientTemplate, err := template.New("client").Parse(string(clientTemplateStr))
	if err != nil {
		return "", err
	}

	partials := make([]string, endpointCount)

	buf := new(bytes.Buffer)
	i := 0
	for ; i < endpointCount/3; i++ {
		vals := ManifestValues{i}
		serverTemplate.Execute(buf, vals)
		partials[i] = buf.String()
	}

	for ; i < endpointCount; i++ {
		vals := ManifestValues{i}
		clientTemplate.Execute(buf, vals)
		partials[i] = buf.String()
	}

	result := strings.Join(partials, "\n---\n")
	ioutil.WriteFile(manifestPath, []byte(result), os.ModePerm)

	return result, nil
}
