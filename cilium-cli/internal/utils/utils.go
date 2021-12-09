// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package utils

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
)

var versionRegexp = regexp.MustCompile(`^(v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-zA-Z0-9]+)*|[a-zA-Z0-9-_.@:]*:[a-zA-Z0-9-_.@:]+)$`).MatchString

func CheckVersion(version string) bool {
	return versionRegexp(version)
}

// BuildImagePath builds a fully-qualified image path from the given
// default and user image and version.
//
// NOTE: Currently 'userVersion' is never passed as an empty string as
// it is defaulted on the CLI interface to the default version.
//
// If 'userVersion' can already contains a colon (':') it is simply
// concatenated with the image string. This is useful for using the
// "latest" image in testing with "--version :latest". Without the
// colon 'userVersion' is always prepended with 'v' if it is missing.
// This is also useful for postfixing the image name with "-ci", for
// example ("--version -ci:4fac771179959ca575eb6f993d566653d3bfa167").
func BuildImagePath(userImage, defaultImage, userVersion, defaultVersion string) string {
	if userImage == "" {
		switch {
		case userVersion == "":
			// ':' in defaultVersion?
			if strings.Contains(defaultVersion, ":") {
				return defaultImage + defaultVersion
			}
			return defaultImage + ":" + defaultVersion
		case strings.Contains(userVersion, ":"):
			// userVersion already contains the colon. Useful for ":latest",
			// or for "-ci:<hash>"
			return defaultImage + userVersion
		case !strings.HasPrefix(userVersion, "v"):
			return defaultImage + ":" + "v" + userVersion
		}
		return defaultImage + ":" + userVersion
	}
	// Fully-qualified userImage?
	if strings.Contains(userImage, ":") {
		return userImage
	}
	// ':' in userVersion?
	if strings.Contains(userVersion, ":") {
		return userImage + userVersion
	}
	return userImage + ":" + userVersion
}

type LogFunc func(err error, waitTime string)

type WaitParameters struct {
	RetryInterval   time.Duration
	WarningInterval time.Duration
	Timeout         time.Duration
	Log             LogFunc
}

func (w WaitParameters) retryInterval() time.Duration {
	if w.RetryInterval != time.Duration(0) {
		return w.RetryInterval
	}

	return defaults.WaitRetryInterval
}

func (w WaitParameters) warningInterval() time.Duration {
	if w.WarningInterval != time.Duration(0) {
		return w.WarningInterval
	}

	return defaults.WaitWarningInterval
}

type WaitObserver struct {
	ctx         context.Context
	params      WaitParameters
	lastWarning time.Time
	waitStarted time.Time
	cancel      context.CancelFunc
}

func NewWaitObserver(ctx context.Context, p WaitParameters) *WaitObserver {
	w := &WaitObserver{
		ctx:         ctx,
		params:      p,
		lastWarning: time.Now(),
		waitStarted: time.Now(),
	}

	if p.Timeout != time.Duration(0) {
		w.ctx, w.cancel = context.WithTimeout(ctx, p.Timeout)
	}

	return w
}

func (w *WaitObserver) Cancel() {
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *WaitObserver) Retry(err error) error {
	if w.params.Log != nil && time.Since(w.lastWarning) > w.params.warningInterval() {
		waitString := time.Since(w.waitStarted).Truncate(time.Second).String()
		w.params.Log(err, waitString)
		w.lastWarning = time.Now()
	}

	select {
	case <-w.ctx.Done():
		if err != nil {
			return fmt.Errorf("timeout while waiting for condition, last error: %s", err)
		}
		return fmt.Errorf("timeout while waiting for condition")
	case <-time.After(w.params.retryInterval()):
	}

	return nil
}

func Contains(l []string, v string) bool {
	for _, s := range l {
		if s == v {
			return true
		}
	}
	return false
}
