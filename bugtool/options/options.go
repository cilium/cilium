// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package options

import (
	"fmt"
	"runtime"
	"time"

	apiserverOption "github.com/cilium/cilium/clustermesh-apiserver/option"
	operatorOption "github.com/cilium/cilium/operator/option"
	ciliumOptions "github.com/cilium/cilium/pkg/option"

	"github.com/spf13/pflag"
	"go.uber.org/multierr"
)

const DefaultDumpPath = "/tmp"

type Config struct {
	Archive           bool          `mapstructure:"archive"`
	ArchiveName       string        `mapstructure:"archive-name"`
	ArchiveType       string        `mapstructure:"archiveType"`
	ArchivePrefix     string        `mapstructure:"archive-prefix"`
	Topics            []string      `mapstructure:"topics"`
	DumpPath          string        `mapstructure:"tmp"`
	ExecTimeout       time.Duration `mapstructure:"exec-timeout"`
	ConfigFile        string        `mapstructure:"config"`
	GetPProf          bool          `mapstructure:"get-pprof"`
	PprofPort         int           `mapstructure:"pprof-port"`
	PprofDebug        int           `mapstructure:"pprof-debug"`
	PProfTraceSeconds int           `mapstructure:"pprof-trace-seconds"`
	EnvoyDump         bool          `mapstructure:"envoy-dump"`

	ParallelWorkers    int           `mapstructure:"parallel-workers"`
	ExcludeObjectFiles bool          `mapstructure:"exclude-object-files"`
	Generate           bool          `mapstructure:"generate"`
	Timeout            time.Duration `mapstructure:"timeout"`
	Debug              bool          `mapstructure:"debug"`
	Wait               bool          `mapstructure:"wait"`
	WaitTimeout        time.Duration `mapstructure:"wait-timeout"`

	DryRun bool `mapstructure:"dry-run"` // Deprecated.
}

var (
	DefaultTopics = []string{"bpfmaps", "agent", "system", "envoy"}
	AllTopics     = append(DefaultTopics, "envoy")
)

func (bugtoolConf *Config) Flags(flags *pflag.FlagSet) {
	// Dump tasks
	flags.StringSliceVar(&bugtoolConf.Topics, "topics", DefaultTopics, fmt.Sprintf("Select dump tasks to run by available topics: %v", AllTopics))

	// Archive
	flags.BoolVar(&bugtoolConf.Archive, "archive", true, "Create archive when false skips deletion of the output directory")
	flags.StringVar(&bugtoolConf.ArchiveName, "archive-name", "", "Override default dump archive naming scheme (if --archive is true)")
	flags.StringVarP(&bugtoolConf.ArchiveType, "archiveType", "o", "tar", "Archive type: tar | gz")
	flags.StringVarP(&bugtoolConf.ArchivePrefix, "archive-prefix", "", "", "String to prefix to name of archive if created (e.g., with cilium pod-name)")
	flags.StringVarP(&bugtoolConf.DumpPath, "tmp", "t", DefaultDumpPath, "Path to store extracted files. Use '-' to send to stdout.")

	flags.BoolVar(&bugtoolConf.GetPProf, "get-pprof", false, "When set, only gets the pprof traces from the cilium-agent binary")
	flags.MarkDeprecated("get-pprof", "Use --topics=pprof instead")
	flags.IntVar(&bugtoolConf.PprofDebug, "pprof-debug", 1, "Debug pprof args")
	flags.BoolVar(&bugtoolConf.EnvoyDump, "envoy-dump", false, "When set, dump envoy configuration from unix socket")
	flags.MarkDeprecated("envoy-dump", "Use --topics=envoy instead")
	flags.IntVar(&bugtoolConf.PprofPort,
		"pprof-port", ciliumOptions.PprofPortAgent,
		fmt.Sprintf(
			"Pprof port to connect to. Known Cilium component ports are agent:%d, operator:%d, apiserver:%d",
			ciliumOptions.PprofPortAgent, operatorOption.PprofPortOperator, apiserverOption.PprofPortAPIServer,
		),
	)
	flags.IntVar(&bugtoolConf.PProfTraceSeconds, "pprof-trace-seconds", 180, "Amount of seconds used for pprof CPU traces")
	flags.BoolVar(&bugtoolConf.Generate, "generate", false, "Create configuration file of all commands that would have been executed")
	flags.BoolVar(&bugtoolConf.DryRun, "dry-run", false, "Create configuration file of all commands that would have been executed")
	flags.MarkDeprecated("dry-run", "use --generate instead")
	flags.DurationVarP(&bugtoolConf.ExecTimeout, "exec-timeout", "", 30*time.Second, "The default timeout for any cmd execution in seconds")
	flags.StringVarP(&bugtoolConf.ConfigFile, "config", "", "", "Configuration to decide what should be run")
	flags.IntVar(&bugtoolConf.ParallelWorkers, "parallel-workers", runtime.NumCPU(), "Maximum number of parallel worker tasks, use 0 for number of CPUs")
	flags.DurationVar(&bugtoolConf.Timeout, "timeout", 30*time.Second, "Dump timeout seconds")
	flags.BoolVar(&bugtoolConf.Debug, "debug", false, "Enable debug logging")
	flags.BoolVar(&bugtoolConf.ExcludeObjectFiles, "exclude-object-files", false, "Exclude per-endpoint object files. Template object files will be kept")

	flags.BoolVar(&bugtoolConf.Wait, "wait", true, "Wait for agent to be ready before attempting dump, avoids trying to get data that hasn't been initialized yet")
	flags.DurationVar(&bugtoolConf.WaitTimeout, "wait-timeout", 20*time.Second, "Timeout to use while waiting for agent to be ready")
}

// Validate validates bugtool configuration.
func (bugtoolConf *Config) Validate() error {
	var acc error
	if err := isValidArchiveType(bugtoolConf.ArchiveType); err != nil {
		acc = multierr.Append(acc, err)
	}
	return acc
}

func isValidArchiveType(archiveType string) error {
	switch archiveType {
	case
		"tar",
		"gz":
		return nil
	}
	return fmt.Errorf("invalid archive type %q", archiveType)
}
