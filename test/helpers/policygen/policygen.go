package policygen

var policiesTestSuite = PolicyTestSuite{
	l3Checks: []PolicyTest{
		PolicyTest{
			name:  "No Policy",
			kind:  ingress,
			tests: ConnResultAllOK,
			template: map[string]string{
				"FromEndpoints": `[{}]`,
			},
		},
		PolicyTest{
			name:  "Ingress Label",
			kind:  ingress,
			tests: ConnResultAllOK,
			template: map[string]string{
				"FromEndpoints": `[{"matchLabels": { "id": "{{.SrcPod}}"}}]`,
			},
		},
		PolicyTest{
			name:  "Ingress Label Invalid",
			kind:  ingress,
			tests: ConnResultAllTimeout,
			template: map[string]string{
				"FromEndpoints": `[{"matchLabels": { "id": "{{.SrcPod}}Invalid"}}]`,
			},
		},
	},
	l4Checks: []PolicyTest{
		PolicyTest{
			name:     "No Policy",
			kind:     ingress,
			tests:    ConnResultAllOK,
			template: map[string]string{},
		},
		PolicyTest{
			name:  "Ingress Port 80 No protocol",
			kind:  ingress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"Ports": `[{"port": "80"}]`,
			},
		},
		PolicyTest{
			name:  "Ingress Port 80 TCP",
			kind:  ingress,
			tests: ConnResultOnlyHTTP,
			template: map[string]string{
				"Ports": `[{"port": "80", "protocol": "TCP"}]`,
			},
		},
		PolicyTest{
			name:  "Ingress Port 80 UDP",
			kind:  ingress,
			tests: ConnResultAllTimeout,
			template: map[string]string{
				"Ports": `[{"port": "80", "protocol": "UDP"}]`,
			},
		},
	},
	l7Checks: []PolicyTest{
		PolicyTest{
			name:     "No Policy",
			kind:     ingress,
			tests:    ConnResultAllOK,
			template: map[string]string{},
		},
		PolicyTest{
			name:  "Ingress policy /private/",
			kind:  ingress,
			tests: ConnResultOnlyHTTPPrivate,
			template: map[string]string{
				"Rules": `{"http": [{"method": "GET", "path": "/private"}]}`,
			},
		},
		PolicyTest{
			name:  "Egress policy to /private/",
			kind:  egress,
			tests: ConnResultOnlyHTTPPrivate,
			template: map[string]string{
				"Rules": `{"http": [{"method": "GET", "path": "/private"}]}`,
			},
		},
	},
}

// GeneratedTestSpec retuns a `TestSpec` array with all the policies
// possibilities
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
