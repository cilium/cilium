// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

import (
	"fmt"
	"time"
)

func PrettySince(t time.Time) string {
	return PrettyDuration(time.Since(t))
}

func PrettyDuration(d time.Duration) string {
	ago := float64(d) / float64(time.Microsecond)

	// micros
	if ago < 1000.0 {
		return fmt.Sprintf("%.1fus", ago)
	}

	// millis
	ago /= 1000.0
	if ago < 1000.0 {
		return fmt.Sprintf("%.1fms", ago)
	}
	// secs
	ago /= 1000.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fs", ago)
	}
	// mins
	ago /= 60.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fm", ago)
	}
	// hours
	ago /= 60.0
	return fmt.Sprintf("%.1fh", ago)
}
