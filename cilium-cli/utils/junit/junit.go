// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package junit

import (
	"fmt"
	"os"
	"strings"
)

func NamespacedFileName(namespace string, junitFile string) string {
	if junitFile == "" {
		return ""
	}
	idx := strings.LastIndex(junitFile, string(os.PathSeparator))
	if idx == -1 {
		return fmt.Sprintf("%s-%s", namespace, junitFile)
	}
	return fmt.Sprintf("%s%s-%s", junitFile[:idx+1], namespace, junitFile[idx+1:])
}
