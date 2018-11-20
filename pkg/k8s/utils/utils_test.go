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

// +build !privileged_tests

package utils

import (
	. "gopkg.in/check.v1"
)

func (s *FactorySuite) TestIsInfraContainer(c *C) {
	type args struct {
		labels map[string]string
	}
	type want struct {
		IsInfraContainer bool
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "non infra container",
			setupArgs: func() args {
				return args{
					labels: map[string]string{
						"annotation.io.kubernetes.container.terminationMessagePath":   "/dev/termination-log",
						"io.kubernetes.docker.type":                                   "container",
						"io.kubernetes.pod.name":                                      "guestbook-xt4gk",
						"io.kubernetes.pod.uid":                                       "e01003fb-e379-11e8-b8e7-0800271bbcb9",
						"io.kubernetes.sandbox.id":                                    "03aa8c8d48e423fffcdd7c3e9a3d319197c064520598142c17638508dd4c83df",
						"annotation.io.kubernetes.container.hash":                     "84a5e346",
						"annotation.io.kubernetes.container.restartCount":             "69",
						"annotation.io.kubernetes.container.terminationMessagePolicy": "File",
						"annotation.io.kubernetes.pod.terminationGracePeriod":         "30",
						"io.kubernetes.container.logpath":                             "/var/log/pods/e01003fb-e379-11e8-b8e7-0800271bbcb9/guestbook/69.log",
						"io.kubernetes.container.name":                                "guestbook",
						"io.kubernetes.pod.namespace":                                 "kube-system",
					},
				}
			},
			setupWant: func() want {
				return want{
					false,
				}
			},
		},
		{
			name: "infra container",
			setupArgs: func() args {
				return args{
					labels: map[string]string{
						"annotation.kubernetes.io/config.seen":   "2018-11-08T17:15:22.477743596Z",
						"io.kubernetes.docker.type":              "podsandbox",
						"pod-template-generation":                "1",
						"annotation.kubernetes.io/config.source": "api",
						"app":                                    "guestbook",
						"controller-revision-hash":               "677b87bff7",
						"io.kubernetes.container.name":           "POD",
						"io.kubernetes.pod.name":                 "guestbook-xt4gk",
						"io.kubernetes.pod.namespace":            "kube-system",
						"io.kubernetes.pod.uid":                  "e01003fb-e379-11e8-b8e7-0800271bbcb9",
					},
				}
			},
			setupWant: func() want {
				return want{
					true,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		got := IsInfraContainer(args.labels)
		c.Assert(got, Equals, want.IsInfraContainer, Commentf("Test Name: %s", tt.name))
	}
}
