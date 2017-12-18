package policygen

import (
	"time"

	"github.com/cilium/cilium/test/helpers"
)

var (
	ConnTests        = []string{Ping, HTTP, HTTPPrivate}
	ConnTestsResults = []ResultType{
		ResultTimeout,
		ResultAuth,
		ResultOK,
	}
	ConnTestsActions = map[string]func(srcPod string, dest *TargetDetails, kub *helpers.Kubectl) *ResultType{
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
		Target{Kind: service},
		Target{Kind: nodePort},
		Target{Kind: direct},
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
