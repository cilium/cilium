// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logutils

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
type LogutilsTestSuite struct{}

var _ = Suite(&LogutilsTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LogutilsTestSuite) TestLogErrorsSummary(c *C) {
	log := `Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="Process exited" cmd="cilium-health [-d]" exitCode="<nil>" subsys=launcher
Mar 05 07:51:17 runtime cilium-agent[11336]: level=warning msg="Error while running monitor" error="Unable to read stdout from monitor: EOF" subsys=monitor-launcher
Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="Sleeping with exponential backoff" attempt=1 fields.time=2s name=75419b5f-3f1b-11e9-9375-080027b5ed00 subsys=backoff
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=3
Mar 05 07:51:17 runtime cilium-agent[11336]: level=info msg="Envoy: Closing access log connection" subsys=envoy-manager
Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="xDS stream closed" subsys=xds xdsStreamID=3
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="error while receiving request from xDS stream" error="rpc error: code = Canceled desc = context canceled" subsys=xds xdsStreamID=2
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=1
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=1
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="error while receiving request from xDS stream" error="rpc error: code = Canceled desc = context canceled" subsys=xds xdsStreamID=1
2019-03-11T11:42:29.197427096Z level=error msg=k8sError error="github.com/cilium/cilium/daemon/k8s_watcher.go:847: expected type *v1.Node, but watch event object had type *v1.Namespace" subsys=k8s`

	output := LogErrorsSummary(log)

	expected := `Number of "context deadline exceeded" in logs: 0
⚠️  Number of "level=error" in logs: 6
Number of "level=warning" in logs: 1
Number of "Cilium API handler panicked" in logs: 0
Number of "Goroutine took lock for more than" in logs: 0
Top 4 errors/warnings:
xDS stream context canceled
error while receiving request from xDS stream
github.com/cilium/cilium/daemon/k8s_watcher.go:847: expected type *v1.Node, but watch event object had type *v1.Namespace
Error while running monitor
`

	c.Assert(output, Equals, expected)

	output = LogErrorsSummary("")
	expected = `Number of "context deadline exceeded" in logs: 0
Number of "level=error" in logs: 0
Number of "level=warning" in logs: 0
Number of "Cilium API handler panicked" in logs: 0
Number of "Goroutine took lock for more than" in logs: 0
No errors/warnings found in logs
`

	c.Assert(output, Equals, expected)
}
