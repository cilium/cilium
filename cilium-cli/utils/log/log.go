// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package log

import "strings"

// Reduce function filters log messages
// and returns only valuable data (warn, err, fatal)
// in case of verbose all the messages will be returned
func Reduce(logs string, verbose bool) string {
	logs = strings.TrimSpace(logs)
	if verbose {
		return logs
	}

	// If the log is small, just print the whole thing.
	context := 5 // lines
	lines := strings.Split(logs, "\n")
	if len(lines) <= context*2 {
		return logs
	}

	// There's a few critical things in most logs:
	// - A few of the oldest lines from initial startup
	// - A few of the newest lines with the final error
	// - Anything marked with warning level or higher severity
	truncated := false
	result := lines[:context]
	for i := context; i < len(lines); i++ {
		// Always keep the end of the log
		if i >= len(lines)-context {
			result = append(result, lines[i])
			continue
		}

		// Keep serious-looking logs
		switch {
		case strings.Contains(lines[i], "level=warn"):
			result = append(result, lines[i])
			truncated = false
		case strings.Contains(lines[i], "level=err"):
			result = append(result, lines[i])
			truncated = false
		case strings.Contains(lines[i], "level=fatal"):
			result = append(result, lines[i])
			truncated = false
		default:
			if !truncated {
				result = append(result, "<...>")
				truncated = true
			}
		}
	}

	return strings.Join(result, "\n")
}
