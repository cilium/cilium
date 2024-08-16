// Copyright 2020-2021 Authors of Cilium
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

package tests

func curlCommand(target string) []string {
	return []string{"curl", "-w", "%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}\n", "--silent", "--fail", "--show-error", "--connect-timeout", "5", "--output", "/dev/null", target}
}
