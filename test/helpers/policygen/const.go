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

import (
	"time"

	"github.com/cilium/cilium/test/helpers"
)

var (
	ConnTests              = []string{Ping, HTTP, HTTPPrivate}
	ConnTestsFailedResults = []ResultType{
		ResultTimeout,
		ResultAuth,
	}
	ConnTestsActions = map[string]func(srcPod string, dest TargetDetails, kub *helpers.Kubectl) ResultType{
		Ping:        PingAction,
		HTTP:        HTTPActionPublic,
		HTTPPrivate: HTTPActionPrivate,
	}

	ConnResultAllOK = ConnTestSpec{
		HTTP:        ResultOK,
		HTTPPrivate: ResultOK,
		Ping:        ResultOK,
		UDP:         ResultOK,
	}

	ConnResultAllTimeout = ConnTestSpec{
		HTTP:        ResultTimeout,
		HTTPPrivate: ResultTimeout,
		Ping:        ResultTimeout,
		UDP:         ResultTimeout,
	}

	ConnResultOnlyHTTP = ConnTestSpec{
		HTTP:        ResultOK,
		HTTPPrivate: ResultOK,
		Ping:        ResultTimeout,
		UDP:         ResultTimeout,
	}

	ConnResultOnlyHTTPPrivate = ConnTestSpec{
		HTTP:        ResultAuth,
		HTTPPrivate: ResultOK,
		Ping:        ResultTimeout,
		UDP:         ResultTimeout,
	}

	DestinationsTypes = []Target{
		{Kind: service},
		{Kind: nodePort},
		{Kind: direct},
	}

	NodePortStart = 10000

	ResultTimeout = ResultType{"timeout", false}
	ResultAuth    = ResultType{"reply", false}
	ResultOK      = ResultType{"reply", true}
)

const (
	ingress = "ingress"
	egress  = "egress"
	toPorts = "ToPorts"

	HTTP        = "HTTP"
	HTTPPrivate = "HTTPPrivate"
	Ping        = "Ping"
	UDP         = "UDP"

	service  = "service"
	nodePort = "NodePort"
	direct   = "Direct"

	destroyDelay time.Duration = 30 * time.Minute
)
