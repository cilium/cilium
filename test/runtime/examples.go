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

package RuntimeTest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimePolicyValidationTests", func() {
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	It("Validates Example Policies", func() {
		By("Validating Demos")

		// Helper function which returns the path to all files in directory dir
		// and all of dir's subdirectories with suffix extension. The file paths
		// returned contain the path without the prefix dir. This allows for
		// gathering of the list of files on the host and for the validation
		// of the policy files to occur the VM, as the root directory of Cilium
		// is different in each environment.
		getFilesWithExtensionFromDir := func(dir, extension string) ([]string, error) {
			fileNames := []string{}

			walkFunc := func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if strings.HasSuffix(info.Name(), extension) {
					relativePath := strings.TrimPrefix(path, dir)
					fileNames = append(fileNames, relativePath)
				}
				return nil
			}

			err := filepath.Walk(dir, walkFunc)
			if err != nil {
				return nil, err
			}

			filesWithExtension := []string{}
			for _, file := range fileNames {
				if strings.HasSuffix(file, extension) {
					filesWithExtension = append(filesWithExtension, file)
				}
			}
			return filesWithExtension, nil
		}

		examplesDemoPath := "examples/demo"
		examplesPoliciesPath := "examples/policies"
		examplePathHost := filepath.Join("..", examplesDemoPath)
		jsonFiles, err := getFilesWithExtensionFromDir(examplePathHost, "json")
		Expect(err).Should(BeNil(), "Unable to get files at path %s: %s", examplePathHost, err)

		examplePathVM := filepath.Join(helpers.BasePath, "..", examplesDemoPath)
		for _, file := range jsonFiles {
			jsonPolicyPath := filepath.Join(examplePathVM, file)
			vm.ExecCilium(fmt.Sprintf("policy validate %s", jsonPolicyPath)).ExpectSuccess("Unable to validate policy %s", jsonPolicyPath)
		}

		By("Validating JSON Examples")

		jsonExamplesPathHost := filepath.Join("..", examplesPoliciesPath)
		jsonFiles, err = getFilesWithExtensionFromDir(jsonExamplesPathHost, "json")
		Expect(err).Should(BeNil(), "Unable to get files at path %s: %s", jsonExamplesPathHost, err)

		jsonExamplesPathVM := filepath.Join(helpers.BasePath, "..", examplesPoliciesPath)
		for _, file := range jsonFiles {
			jsonPolicyPath := filepath.Join(jsonExamplesPathVM, file)
			vm.ExecCilium(fmt.Sprintf("policy validate %s", jsonPolicyPath)).ExpectSuccess("Unable to validate policy %s", jsonPolicyPath)
		}

		By("Validating YAML Examples")

		yamlExamplesPathHost := filepath.Join("..", examplesPoliciesPath)
		jsonFiles, err = getFilesWithExtensionFromDir(yamlExamplesPathHost, "yaml")
		Expect(err).Should(BeNil(), "Unable to get files at path %s: %s", yamlExamplesPathHost, err)

		yamlExamplesPathVM := filepath.Join(helpers.BasePath, "..", examplesPoliciesPath)
		for _, file := range jsonFiles {
			yamlPolicyPath := filepath.Join(yamlExamplesPathVM, file)
			res := vm.Exec(fmt.Sprintf("yamllint -c %s %s", filepath.Join(helpers.BasePath, "yaml.config"), yamlPolicyPath))
			res.ExpectSuccess("Unable to validate YAML %s", yamlPolicyPath)
		}
	})
})
