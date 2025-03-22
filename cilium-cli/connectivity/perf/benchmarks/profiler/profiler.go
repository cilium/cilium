// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package profiler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

type logger interface {
	Debugf(format string, args ...any)
}

type Profiler struct {
	enabled   bool
	target    check.Pod
	duration  time.Duration
	reportDir string
}

type Profile struct {
	enabled   bool
	reportDir string
	grp       errgroup.Group
	data      bytes.Buffer
}

func New(target check.Pod, params check.PerfParameters) *Profiler {
	return &Profiler{
		enabled:   params.KernelProfiles,
		target:    target,
		duration:  params.Duration,
		reportDir: params.ReportDir,
	}
}

func (p *Profiler) Run(ctx context.Context, logger logger) *Profile {
	if !p.enabled {
		return &Profile{}
	}

	profile := &Profile{enabled: true, reportDir: p.reportDir}
	profile.grp.Go(func() (err error) {
		profile.data, err = p.run(ctx, logger)
		return err
	})

	return profile
}

func (p *Profiler) run(ctx context.Context, logger logger) (bytes.Buffer, error) {
	var (
		// Sleep one tenth of the test duration before starting to record the profile,
		// and symmetrically stop the profile one tenth of the duration before the end,
		// so that we increase the likelihood of only capturing the profile during the
		// active period, considering that it is started via a separate exec operation.
		delay    = strconv.FormatInt(p.duration.Milliseconds()/10, 10)
		duration = strconv.FormatFloat(p.duration.Seconds()*0.8, 'f', 1, 64)

		nsenter = []string{"nsenter", "--target=1", "--mount", "--"}
		record  = []string{"perf", "record", "--freq", "99", "--all-cpus", "-g", "--delay", delay, "-o", "/tmp/perf.data", "--", "sleep", duration}
		script  = []string{"perf", "script", "-i", "/tmp/perf.data"}
	)

	logger.Debugf("Starting profile capture on %s: %s", p.target.Name(), strings.Join(slices.Concat(nsenter, record), " "))
	_, stderr, err := p.target.K8sClient.ExecInPodWithStderr(ctx, p.target.Namespace(), p.target.NameWithoutNamespace(),
		"profiler", slices.Concat(nsenter, record))
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("capturing profile: %w: %v", err, stderr.String())
	}

	logger.Debugf("Parsing profile on %s: %s", p.target.Name(), strings.Join(slices.Concat(nsenter, script), " "))
	stdout, stderr, err := p.target.K8sClient.ExecInPodWithStderr(ctx, p.target.Namespace(), p.target.NameWithoutNamespace(),
		"profiler", slices.Concat(nsenter, script))
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("parsing profile: %w: %v", err, stderr.String())
	}
	logger.Debugf("Profile successfully retrieved from %s", p.target.Name())

	return stdout, nil
}

func (p *Profile) Save(filename string, logger logger) error {
	if !p.enabled {
		return nil
	}

	if err := p.grp.Wait(); err != nil {
		return err
	}

	target := path.Join(p.reportDir, filename)
	if err := os.WriteFile(target, p.data.Bytes(), 0600); err != nil {
		return fmt.Errorf("saving profile: %w", err)
	}
	logger.Debugf("Profile saved to %q", target)

	return nil
}
