// Copyright 2021 Authors of Cilium
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

package cmd

import "fmt"

const lpmWarningMessage = `
Note that for Linux kernel versions between 4.11 and 4.15 inclusive, the native
LPM map type used for implementing this feature does not provide the ability to
walk / dump the entries, so on these kernel versions this tool will never
return any entries, even if entries exist in the map. `

const suggestionTemplate = `You may instead run:
    cilium map get %s
`

func lpmKernelVersionWarning(mapName string) string {
	if mapName == "" {
		return lpmWarningMessage
	}

	return lpmWarningMessage + fmt.Sprintf(suggestionTemplate, mapName)
}
