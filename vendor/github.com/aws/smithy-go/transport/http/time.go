package http

import (
	"fmt"
	"time"
)

// Time parsing function sourced from stdlib with an additional time format so
// non-compliant timestamps are still parseable.
// https://github.com/golang/go/blob/8869086d8f0a31033ccdc103106c768dc17216b1/src/net/http/header.go#L110-L127
var timeFormats = []string{
	"Mon, _2 Jan 2006 15:04:05 GMT", // Modifies http.TimeFormat with a leading underscore for day number (leading 0 optional).
	"Mon, _2 Jan 06 15:04:05 GMT",   // two digit year
	time.RFC850,
	time.ANSIC,
}

// ParseTime parses a time header like the HTTP Date header.
// This uses a more relaxed rule set for date parsing compared to the standard library.
func ParseTime(text string) (t time.Time, err error) {
	for _, layout := range timeFormats {
		t, err = time.Parse(layout, text)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unknown time format: %w", err)
}
