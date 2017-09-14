/*
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

package candiedyaml

import (
	"io/ioutil"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var scan = func(filename string) {
	It("scan "+filename, func() {
		file, err := os.Open(filename)
		Expect(err).To(BeNil())

		parser := yaml_parser_t{}
		yaml_parser_initialize(&parser)
		yaml_parser_set_input_reader(&parser, file)

		failed := false
		token := yaml_token_t{}

		for {
			if !yaml_parser_scan(&parser, &token) {
				failed = true
				break
			}

			if token.token_type == yaml_STREAM_END_TOKEN {
				break
			}
		}

		file.Close()

		// msg := "SUCCESS"
		// if failed {
		// 	msg = "FAILED"
		// 	if parser.error != yaml_NO_ERROR {
		// 		m := parser.problem_mark
		// 		fmt.Printf("ERROR: (%s) %s @ line: %d  col: %d\n",
		// 			parser.context, parser.problem, m.line, m.column)
		// 	}
		// }
		Expect(failed).To(BeFalse())
	})
}

var scanYamls = func(dirname string) {
	fileInfos, err := ioutil.ReadDir(dirname)
	if err != nil {
		panic(err.Error())
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			scan(filepath.Join(dirname, fileInfo.Name()))
		}
	}
}

var _ = Describe("Scanner", func() {
	scanYamls("fixtures/specification")
	scanYamls("fixtures/specification/types")
})
