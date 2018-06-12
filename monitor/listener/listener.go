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

package listener

import (
	"github.com/cilium/cilium/monitor/payload"
)

type ListenerVersion string

const (
	ListenerVersionUnsupported = ListenerVersion("unsupported")
	ListenerVersion1_0         = ListenerVersion("1.0")
)

// MonitorListener is a generic consumer of monitor events. Implementers are
// expected to handle errors as needed, including exiting.
type MonitorListener interface {
	// Enqueue adds this payload to the send queue. Any errors should be logged
	// and handled appropriately.
	Enqueue(pl *payload.Payload)

	// Version returns the API version of this listener
	Version() ListenerVersion
}
