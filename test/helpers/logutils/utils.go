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
	"regexp"
	"sort"
	"strings"
)

const (
	selfishThresholdMsg = "Goroutine took lock for more than" // from https://github.com/cilium/cilium/pull/5268

	contextDeadlineExceeded = "context deadline exceeded"
	errorLogs               = "level=error"
	warningLogs             = "level=warning"
	aPIPanicked             = "Cilium API handler panicked"
)

var countLogsMessages = []string{contextDeadlineExceeded, errorLogs, warningLogs, aPIPanicked, selfishThresholdMsg}

// LogErrorsSummary returns error and warning summary for given logs
func LogErrorsSummary(logs string) string {
	var sb strings.Builder
	for _, message := range countLogsMessages {
		var prefix = ""
		result := strings.Count(logs, message)
		if result > 5 {
			// Added a warning emoji just in case that are more than 5 warning in the logs.
			prefix = "⚠️  "
		}
		fmt.Fprintf(&sb, "%sNumber of %q in logs: %d\n", prefix, message, result)
	}
	sb.WriteString("Top 5 errors/warnings:\n")

	warns := getErrorWarningMsgs(logs, 5)
	sb.WriteString(strings.Join(warns, "\n"))
	return sb.String()
}

func getErrorWarningMsgs(logs string, n int) []string {
	msgRegex := regexp.MustCompile(`msg=".*?"( |$)`)
	errors := map[string]int{}
	warnings := map[string]int{}
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, errorLogs) {
			msg := msgRegex.FindString(line)
			msg = msg[5 : len(msg)-2]
			errors[msg]++
		} else if strings.Contains(line, warningLogs) {
			msg := msgRegex.FindString(line)
			msg = msg[5 : len(msg)-2]
			warnings[msg]++
		}
	}

	errs := make([]message, 0, len(errors)+len(warnings))

	for msg, count := range errors {
		errs = append(errs, message{msg, count, true})
	}

	for msg, count := range warnings {
		errs = append(errs, message{msg, count, false})
	}

	sort.Sort(sort.Reverse(byImportance(errs)))

	if n > len(errs) {
		n = len(errs)
	}

	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = errs[i].msg
	}
	return result
}

type message struct {
	msg     string
	count   int
	isError bool
}

type byImportance []message

// Len is part of sort.Interface
func (s byImportance) Len() int {
	return len(s)
}

// Swap is part of sort.Interface
func (s byImportance) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less is part of sort.Interface
func (s byImportance) Less(i, j int) bool {
	return (!s[i].isError && s[j].isError) || s[i].count < s[j].count
}
