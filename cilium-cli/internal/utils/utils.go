// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver/v4"

	"github.com/cilium/cilium-cli/defaults"
)

var versionRegexp = regexp.MustCompile(`^((v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-zA-Z0-9.]+)*|[a-zA-Z0-9-_.@:]*:[a-zA-Z0-9-_.@:]+)|([0-9a-fA-F]{40})|(latest))$`).MatchString

func CheckVersion(version string) error {
	if !versionRegexp(version) && version != "" {
		return fmt.Errorf("invalid syntax %q for image tag", version)
	}
	return nil
}

func ParseCiliumVersion(version string) (semver.Version, error) {
	return semver.ParseTolerant(version)
}

type ImagePathMode int

const (
	ImagePathExcludeDigest ImagePathMode = iota
	ImagePathIncludeDigest
	CLIModeVariableName = "CILIUM_CLI_MODE"
)

var imageRegexp = regexp.MustCompile(`\A(.*?)(?:(:.*?)(@sha256:[0-9a-f]{64})?)?\z`)

// BuildImagePath builds a fully-qualified image path from the given
// user image and version and default image.
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
//
// If imagePathMode is ImagePathIncludeDigest and the resulting image is well
// known (i.e. is in defaults.WellKnownImageDigests) then its digest is appended
// to the path.
func BuildImagePath(userImage, userVersion, defaultImage, defaultVersion string, imagePathMode ImagePathMode) string {
	var image string
	switch {
	case userImage == "" && userVersion == "":
		if strings.Contains(defaultVersion, ":") {
			image = defaultImage + defaultVersion
		} else {
			image = defaultImage + ":" + defaultVersion
		}
	case userImage == "" && strings.Contains(userVersion, ":"):
		// userVersion already contains the colon. Useful for ":latest",
		// or for "-ci:<hash>"
		image = defaultImage + userVersion
	case userImage == "" && !strings.HasPrefix(userVersion, "v"):
		image = defaultImage + ":v" + userVersion
	case userImage == "":
		image = defaultImage + ":" + userVersion
	case strings.Contains(userImage, ":"):
		// Fully-qualified userImage?
		image = userImage
	case strings.Contains(userVersion, ":"):
		// ':' in userVersion?
		image = userImage + userVersion
	default:
		image = userImage + ":" + userVersion
	}

	switch imagePathMode {
	case ImagePathIncludeDigest:
		image = image + defaults.WellKnownImageDigests[image]
	case ImagePathExcludeDigest:
		if m := imageRegexp.FindStringSubmatch(image); m != nil {
			image = m[1] + m[2]
		}
	}
	return image
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

// IsInHelmMode returns true if cilium-cli is in "helm" mode. Otherwise, it returns false.
func IsInHelmMode() bool {
	return os.Getenv(CLIModeVariableName) == "helm"
}
