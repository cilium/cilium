// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
