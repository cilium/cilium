// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliuminstall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vladimirvivien/gexe"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

var (
	defaultHelmOptions = map[string]string{
		/*
			"image.repository":              "quay.io/cilium/cilium-ci",
			"image.tag":                     "latest",
			"image.useDigest":               "false",
			"operator.image.repository":     "quay.io/cilium/operator",
			"operator.image.suffix":         "-ci",
			"operator.image.tag":            "latest",
			"operator.image.useDigest":      "false",
			"hubble.relay.image.repository": "quay.io/cilium/hubble-relay-ci",
			"hubble.relay.image.tag":        "latest",
			"hubble.relay.image.useDigest":  "false",
		*/
		"debug.enabled": "true",
	}
)

type Opts struct {
	Wait           bool
	Namespace      string
	ChartDirectory string
	HelmOptions    map[string]string
}

type Option func(*Opts)

func WithWait(wait bool) Option {
	return func(o *Opts) { o.Wait = wait }
}

func WithNamespace(namespace string) Option {
	return func(o *Opts) { o.Namespace = namespace }
}

func WithChartDirectory(chartDirectory string) Option {
	return func(o *Opts) { o.ChartDirectory = chartDirectory }
}

func WithHelmOptions(helmOptions map[string]string) Option {
	return func(o *Opts) {
		// TODO: copy instead?
		o.HelmOptions = helmOptions
	}
}

func processOpts(opts ...Option) *Opts {
	o := &Opts{}
	for _, op := range opts {
		op(o)
	}
	return o
}

type ciliumCLI struct {
	cmd  string
	opts *Opts
	e    *gexe.Echo
}

func newCiliumCLI(opts *Opts) *ciliumCLI {
	return &ciliumCLI{
		cmd:  "cilium",
		opts: opts,
		e:    gexe.New(),
	}
}

func (c *ciliumCLI) findOrInstall(ctx context.Context) error {
	if _, err := exec.LookPath(c.cmd); err != nil {
		// TODO: try to install cilium-cli using `go install` or similar
		return fmt.Errorf("cilium: cilium-cli not installed or could not be found: %w", err)
	}

	ver := c.e.Run(c.cmd + " version")
	v := strings.Split(ver, "\n")
	if len(v) > 0 {
		klog.Infof("Found cilium-cli version %s", v[0])
	}

	// TODO: check against expected cilium-cli version?

	return nil
}

func (c *ciliumCLI) install(ctx context.Context) error {
	if err := c.findOrInstall(ctx); err != nil {
		return err
	}

	// TODO: determine status of potential previous installation using `cilium status`,
	// e.g. by introducing a `cilium status --brief` flag reporting ready/not ready.

	// Uninstall pre-existing Cilium installation.
	_ = c.uninstall(ctx)

	var opts strings.Builder
	if c.opts.Wait {
		opts.WriteString(" --wait")
	}
	if c.opts.Namespace != "" {
		opts.WriteString(fmt.Sprintf(" --namespace=%s", c.opts.Namespace))
	}
	if c.opts.ChartDirectory != "" {
		opts.WriteString(fmt.Sprintf(" --chart-directory=%s", c.opts.ChartDirectory))
	}
	for k, v := range c.opts.HelmOptions {
		opts.WriteString(fmt.Sprintf(" --helm-set=%s=%s", k, v))
	}

	cmd := fmt.Sprintf("%s install%s", c.cmd, opts.String())
	klog.Infof("Running cilium install command %q", cmd)
	p := c.e.RunProc(cmd)
	if p.Err() != nil || p.ExitCode() != 0 {
		return fmt.Errorf("cilium install command failed: %s: %s", p.Err(), p.Result())
	}

	c.status(ctx, true)

	return nil
}

func (c *ciliumCLI) uninstall(ctx context.Context) error {
	if err := c.findOrInstall(ctx); err != nil {
		return err
	}

	var opts strings.Builder
	if c.opts.ChartDirectory != "" {
		opts.WriteString(fmt.Sprintf("--chart-directory=%s", c.opts.ChartDirectory))
	}

	cmd := fmt.Sprintf("%s uninstall %s", c.cmd, opts.String())
	klog.Infof("Running cilium uninstall command %q", cmd)
	p := c.e.RunProc(cmd)
	if p.Err() != nil || p.ExitCode() != 0 {
		return fmt.Errorf("cilium uninstall command failed: %s: %s", p.Err(), p.Result())
	}

	return nil
}

func (c *ciliumCLI) status(ctx context.Context, wait bool) error {
	if err := c.findOrInstall(ctx); err != nil {
		return err
	}

	var flags string
	if wait {
		flags = "--wait"
	}
	cmd := fmt.Sprintf("%s status %s", c.cmd, flags)
	klog.Infof("Running cilium status command %q", cmd)
	p := c.e.StartProc(cmd)
	if p.Err() != nil {
		return fmt.Errorf("cilium status command failed: %s: %s", p.Err(), p.Result())
	}
	var stdout bytes.Buffer
	if _, err := stdout.ReadFrom(p.StdOut()); err != nil {
		return fmt.Errorf("failed to read from cilium status stdout: %w", err)
	}
	if p.Wait().Err() != nil {
		return fmt.Errorf("cilium status command failed: %s: %w", p.Result(), p.Err())
	}

	klog.Infof("Cilium status\n%s", stdout.String())

	return nil
}

// Setup installs Cilium with the given options.
func Setup(options ...Option) env.Func {
	o := processOpts(options...)
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return ctx, newCiliumCLI(o).install(ctx)
	}
}

// Finish uninstalls Cilium.
func Finish(options ...Option) env.Func {
	o := processOpts(options...)
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		return ctx, newCiliumCLI(o).uninstall(ctx)
	}
}
