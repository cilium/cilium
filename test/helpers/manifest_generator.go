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
	"text/template"
)

// ManifestValues wraps manifest index
type ManifestValues struct {
	Index int
}

// GenerateManifestForEndpoints generates k8s manifests that will create
// endpointCount Cilium endpoints when applied.
// 1/3 of endpoints are servers, the rest are clients.
// returns lastServer index
// Saves generated manifest to manifestPath, also returns it via string
func GenerateManifestForEndpoints(endpointCount int, manifestPath string) (string, int, error) {
	configMapStr, err := ioutil.ReadFile(path.Join(K8sManifestBase, GeneratedHTMLManifest))
	if err != nil {
		return "", 0, err
	}

	serverTemplateStr, err := ioutil.ReadFile(path.Join(K8sManifestBase, GeneratedServerManifest))
	if err != nil {
		return "", 0, err
	}
	serverTemplate, err := template.New("server").Parse(string(serverTemplateStr))
	if err != nil {
		return "", 0, err
	}

	clientTemplateStr, err := ioutil.ReadFile(path.Join(K8sManifestBase, GeneratedClientManifest))
	if err != nil {
		return "", 0, err
	}
	clientTemplate, err := template.New("client").Parse(string(clientTemplateStr))
	if err != nil {
		return "", 0, err
	}

	separator := "\n---\n"
	buf := new(bytes.Buffer)
	buf.Write(configMapStr)
	i := 0
	for ; i < endpointCount/3; i++ {
		buf.WriteString(separator)

		vals := ManifestValues{i}
		serverTemplate.Execute(buf, vals)
	}
	lastServer := i

	for ; i < endpointCount; i++ {
		buf.WriteString(separator)

		vals := ManifestValues{i}
		clientTemplate.Execute(buf, vals)
	}

	result := buf.String()
	ioutil.WriteFile(manifestPath, []byte(result), os.ModePerm)

	return result, lastServer, nil
}
