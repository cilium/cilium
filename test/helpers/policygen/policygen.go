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
package policygen

var policiesTestSuite = PolicyTestSuite{
	l3Checks: []PolicyTestKind{
		{
			name:  "No Policy",
			kind:  ingress,
			tests: ConnResultAllOK,
			template: map[string]string{
				"fromEndpoints": `[{}]`,
			},
		},
		{
			name:  "Ingress Label",
			kind:  ingress,
			tests: ConnResultAllOK,
			template: map[string]string{
				"fromEndpoints": `[{"matchLabels": { "id": "{{.SrcPod}}"}}]`,
			},
		},
		{
			name:  "Ingress Label Invalid",
			kind:  ingress,
			tests: ConnResultAllTimeout,
			template: map[string]string{
				"fromEndpoints": `[{"matchLabels": { "id": "{{.SrcPod}}Invalid"}}]`,
			},
		},
	},
	l4Checks: []PolicyTestKind{
		{
			name:     "No Policy",
			kind:     ingress,
			tests:    ConnResultAllOK,
			template: map[string]string{},
		},
		{
			name:  "Ingress Port 80 No protocol",
			kind:  ingress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"ports": `[{"port": "80"}]`,
			},
		},
		{
			name:  "Egress Port 80 No protocol",
			kind:  egress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"ports": `[{"port": "80"}]`,
			},
		},
		{
			name:  "Ingress Port 80 TCP",
			kind:  ingress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
		},
		{
			name:  "Ingress Port 80 UDP",
			kind:  ingress,
			tests: ConnResultAllTimeout,
			template: map[string]string{
				"ports": `[{"port": "80", "protocol": "UDP"}]`,
			},
		},
		{
			name:  "Egress Port 80 TCP",
			kind:  egress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
		},
		{
			name:  "Egress Port 80 UDP",
			kind:  egress,
			tests: ConnResultAllTimeout,
			template: map[string]string{
				"ports": `[{"port": "80", "protocol": "UDP"}]`,
			},
		},
	},
	l7Checks: []PolicyTestKind{
		{
			name:     "No Policy",
			kind:     ingress,
			tests:    ConnResultAllOK,
			template: map[string]string{},
		},
		{
			name:  "Ingress policy /private/",
			kind:  ingress,
			tests: ConnResultOnlyHTTPPrivate,
			template: map[string]string{
				"rules": `{"http": [{"method": "GET", "path": "/private"}]}`,
				"ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
			exclude: []string{
				"L4:Ingress Port 80 UDP",
				"L4:Ingress Port 80 No protocol",
			},
		},
		{
			name:  "Egress policy to /private/",
			kind:  egress,
			tests: ConnResultOnlyHTTPPrivate,
			template: map[string]string{
				"rules": `{"http": [{"method": "GET", "path": "/private"}]}`,
				"ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
			exclude: []string{
				"L4:Egress Port 80 UDP",
				"L4:Egress Port 80 No protocol",
			},
		},
	},
}

// GeneratedTestSpec returns a `TestSpec` array with all the policies
// possibilities based on all combinations of `policiesTestSuite`
func GeneratedTestSpec() []TestSpec {
	var testSpecs = []TestSpec{}
	for _, l3 := range policiesTestSuite.l3Checks {
		for _, l4 := range policiesTestSuite.l4Checks {
			for _, l7 := range policiesTestSuite.l7Checks {
				for _, dst := range DestinationsTypes {
					testSpecs = append(testSpecs, TestSpec{
						l3:          l3,
						l4:          l4,
						l7:          l7,
						Destination: dst,
					})
				}
			}
		}
	}
	return testSpecs
}

// GetBasicTestSpec returns a very simple TestSpec with a L4 and L7 policy that
// allow traffic only to /private/
func GetBasicTestSpec() TestSpec {
	return TestSpec{
		l3: PolicyTestKind{
			name:  "No Policy",
			kind:  ingress,
			tests: ConnResultAllOK,
			template: map[string]string{
				"FromEndpoints": `[{}]`,
			},
		},
		l4: PolicyTestKind{
			name:  "Ingress Port 80 TCP",
			kind:  ingress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"Ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
		},
		l7: PolicyTestKind{
			name:  "Ingress policy /private/",
			kind:  ingress,
			tests: ConnResultOnlyHTTPPrivate,
			template: map[string]string{
				"Rules": `{"http": [{"method": "GET", "path": "/private"}]}`,
				"Ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
		},
		Destination: DestinationsTypes[0],
	}
}
