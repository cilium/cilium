package time

import (
	"context"
	"math/big"
	"time"
)

const (
	// dateTimeFormat is a IMF-fixdate formatted time https://tools.ietf.org/html/rfc7231.html#section-7.1.1.1
	dateTimeFormat = "2006-01-02T15:04:05.99Z"

	// httpDateFormat is a date time defined by RFC3339 section 5.6 with no UTC offset.
	httpDateFormat = "Mon, 02 Jan 2006 15:04:05 GMT"
)

var millisecondFloat = big.NewFloat(1e3)

// FormatDateTime format value as a date-time (RFC3339 section 5.6)
//
// Example: 1985-04-12T23:20:50.52Z
func FormatDateTime(value time.Time) string {
	return value.Format(dateTimeFormat)
}

// ParseDateTime parse a string as a date-time
//
// Example: 1985-04-12T23:20:50.52Z
func ParseDateTime(value string) (time.Time, error) {
	return time.Parse(dateTimeFormat, value)
}

// FormatHTTPDate format value as a http-date (RFC 7231#section-7.1.1.1 IMF-fixdate)
//
// Example: Tue, 29 Apr 2014 18:30:38 GMT
func FormatHTTPDate(value time.Time) string {
	return value.Format(httpDateFormat)
}

// ParseHTTPDate parse a string as a http-date
//
// Example: Tue, 29 Apr 2014 18:30:38 GMT
func ParseHTTPDate(value string) (time.Time, error) {
	return time.Parse(httpDateFormat, value)
}

// FormatEpochSeconds returns value as a Unix time in seconds with with decimal precision
//
// Example: 1515531081.123
func FormatEpochSeconds(value time.Time) float64 {
	ms := value.UnixNano() / int64(time.Millisecond)
	return float64(ms) / 1e3
}

// ParseEpochSeconds returns value as a Unix time in seconds with with decimal precision
//
// Example: 1515531081.123
func ParseEpochSeconds(value float64) time.Time {
	f := big.NewFloat(value)
	f = f.Mul(f, millisecondFloat)
	i, _ := f.Int64()
	return time.Unix(0, i*1e6).UTC()
}

// SleepWithContext will wait for the timer duration to expire, or the context
// is canceled. Which ever happens first. If the context is canceled the
// Context's error will be returned.
func SleepWithContext(ctx context.Context, dur time.Duration) error {
	t := time.NewTimer(dur)
	defer t.Stop()

	select {
	case <-t.C:
		break
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}
