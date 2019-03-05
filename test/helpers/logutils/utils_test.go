// Copyright 2019 Authors of Cilium
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

package logutils

import (
	"fmt"
)

func ExampleLogErrorsSummary() {
	log := `Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="Process exited" cmd="cilium-health [-d]" exitCode="<nil>" subsys=launcher
Mar 05 07:51:17 runtime cilium-agent[11336]: level=warning msg="Error while running monitor" error="Unable to read stdout from monitor: EOF" subsys=monitor-launcher
Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="Sleeping with exponential backoff" attempt=1 fields.time=2s name=75419b5f-3f1b-11e9-9375-080027b5ed00 subsys=backoff
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=3
Mar 05 07:51:17 runtime cilium-agent[11336]: level=info msg="Envoy: Closing access log connection" subsys=envoy-manager
Mar 05 07:51:17 runtime cilium-agent[11336]: level=debug msg="xDS stream closed" subsys=xds xdsStreamID=3
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="error while receiving request from xDS stream" error="rpc error: code = Canceled desc = context canceled" subsys=xds xdsStreamID=2
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=1
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="xDS stream context canceled" error="context canceled" subsys=xds xdsStreamID=1
Mar 05 07:51:17 runtime cilium-agent[11336]: level=error msg="error while receiving request from xDS stream" error="rpc error: code = Canceled desc = context canceled" subsys=xds xdsStreamID=1`
	fmt.Println(LogErrorsSummary(log))
	// Output:
	// Number of "context deadline exceeded" in logs: 0
	// Number of "level=error" in logs: 5
	// Number of "level=warning" in logs: 1
	// Number of "Cilium API handler panicked" in logs: 0
	// Number of "Goroutine took lock for more than" in logs: 0
	// Top 5 errors/warnings:
	// xDS stream context canceled
	// error while receiving request from xDS stream
	// Error while running monitor
}
