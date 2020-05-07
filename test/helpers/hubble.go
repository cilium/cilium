// Copyright 2020 Authors of Cilium
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

package helpers

import (
	"context"
	"fmt"
	"strings"
)

const (
	// older versions of the Hubble CLI use a different default path
	hubbleSock = "unix:///var/run/cilium/hubble.sock"
)

// HubbleObserve runs `hubble observe --output=json <args>`. JSON output is
// enabled such that CmdRes.FilterLines may be used to grep for specific events
// in the output.
func (s *SSHMeta) HubbleObserve(args ...string) *CmdRes {
	argsCoalesced := ""
	if len(args) > 0 {
		argsCoalesced = strings.Join(args, " ")
	}
	hubbleCmd := fmt.Sprintf("hubble observe --server=%q --output=json %s",
		hubbleSock, argsCoalesced)
	return s.Exec(hubbleCmd)
}

// HubbleObserveFollow runs `hubble observe --follow --output=json <args>`. The
// command is running in the background and will be terminated only once ctx
// is cancelled. JSON output is enabled such that
// CmdRes.WaitUntilMatchFilterLine may be used to wait for specific events in
// the output.
func (s *SSHMeta) HubbleObserveFollow(ctx context.Context, args ...string) *CmdRes {
	argsCoalesced := ""
	if len(args) > 0 {
		argsCoalesced = strings.Join(args, " ")
	}
	hubbleCmd := fmt.Sprintf("hubble observe --server=%q --follow --output=json %s",
		hubbleSock, argsCoalesced)
	return s.ExecInBackground(ctx, hubbleCmd)
}
