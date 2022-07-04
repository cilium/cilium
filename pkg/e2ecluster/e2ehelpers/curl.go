// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package e2ehelpers

import (
	"fmt"
	"strconv"
	"time"
)

const (
	defaultConnectTimeout = 5 * time.Second
	defaultMaxTime        = 20 * time.Second
)

type CurlResultFormat string

const (
	CurlResultFormatStats    CurlResultFormat = `time-> DNS: '%{time_namelookup}(%{remote_ip})', Connect: '%{time_connect}', Transfer '%{time_starttransfer}', total '%{time_total}'`
	CurlResultFormatHTTPCode CurlResultFormat = "%%{http_code}"
)

type curlOpts struct {
	Fail         bool
	ResultFormat CurlResultFormat
	Output       string
	Retries      int
	// ConnectTimeout is the timeout in seconds for the connect() syscall that curl invokes.
	ConnectTimeout time.Duration
	// MaxTime is the hard timeout. It starts when curl is invoked and interrupts curl
	// regardless of whether curl is currently connecting or transferring data. CurlMaxTimeout
	// should be at least 5 seconds longer than ConnectTimeout to provide some time to actually
	// transfer data.
	MaxTime        time.Duration
	AdditionalOpts []string
}

type CurlOption func(*curlOpts)

func WithFail(fail bool) CurlOption {
	return func(o *curlOpts) { o.Fail = fail }
}

func WithResultFormat(outputFormat CurlResultFormat) CurlOption {
	return func(o *curlOpts) { o.ResultFormat = outputFormat }
}

func WithOutput(output string) CurlOption {
	return func(o *curlOpts) { o.Output = output }
}

func WithRetries(retries int) CurlOption {
	return func(o *curlOpts) { o.Retries = retries }
}

func WithConnectTimeout(connectTimeout time.Duration) CurlOption {
	return func(o *curlOpts) { o.ConnectTimeout = connectTimeout }
}

func WithMaxTime(maxTime time.Duration) CurlOption {
	return func(o *curlOpts) { o.MaxTime = maxTime }
}

func WithAdditionalOpts(additionalOpts []string) CurlOption {
	return func(o *curlOpts) { o.AdditionalOpts = additionalOpts }
}

func processCurlOpts(opts ...CurlOption) *curlOpts {
	o := &curlOpts{
		ConnectTimeout: defaultConnectTimeout,
		MaxTime:        defaultMaxTime,
	}
	for _, op := range opts {
		op(o)
	}
	return o
}

func CurlCommandAndArgs(url string, opts ...CurlOption) []string {
	o := processCurlOpts(opts...)

	cmd := []string{"curl", "--path-as-is", "-s", "-D /dev/stderr"}
	if o.Fail {
		cmd = append(cmd, "--fail")
	}
	if o.ResultFormat != "" {
		cmd = append(cmd, "-w", fmt.Sprintf("%q", o.ResultFormat))
	}
	if o.Output != "" {
		cmd = append(cmd, "--output", o.Output)
	}
	if o.Retries > 0 {
		cmd = append(cmd, "--retry", strconv.Itoa(o.Retries))
	}
	if o.ConnectTimeout > 0 {
		cmd = append(cmd, "--connect-timeout", strconv.FormatFloat(o.ConnectTimeout.Seconds(), 'f', -1, 64))
	}
	if o.MaxTime > 0 {
		cmd = append(cmd, "--max-time", strconv.FormatFloat(o.MaxTime.Seconds(), 'f', -1, 64))
	}
	if len(o.AdditionalOpts) > 0 {
		cmd = append(cmd, o.AdditionalOpts...)
	}
	cmd = append(cmd, url)
	return cmd
}
