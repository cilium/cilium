// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	warns := getErrorWarningMsgs(logs, 5)
	if len(warns) > 0 {
		sb.WriteString(fmt.Sprintf("Top %d errors/warnings:\n", len(warns)))
	} else {
		sb.WriteString("No errors/warnings found in logs")
	}
	sb.WriteString(strings.Join(warns, "\n"))
	sb.WriteString("\n")
	return sb.String()
}

// getErrorWarningMsgs takes Cilium log and returns at most `n`
// top occurring error/warning messages
func getErrorWarningMsgs(logs string, n int) []string {

	errors := map[string]int{}
	warnings := map[string]int{}
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, errorLogs) {
			msg := getMsg(line)
			errors[msg]++
		} else if strings.Contains(line, warningLogs) {
			msg := getMsg(line)
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

// getMsg extracts message from log line
func getMsg(logLine string) string {
	msgRegex := regexp.MustCompile(`msg=".*?"`)
	errRegex := regexp.MustCompile(`error=".*?"`)

	msg := msgRegex.FindString(logLine)
	offset := 5
	if len(msg) == 0 {
		msg = errRegex.FindString(logLine)
		offset = 7
	}
	if len(msg) > 0 {
		msg = msg[offset : len(msg)-1]
		return msg
	}
	return ""
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
