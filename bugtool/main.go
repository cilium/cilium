// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.20

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/cilium/bugtool/cmd"
	"github.com/cilium/cilium/bugtool/configuration"
	"github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/workerpool"

	"sigs.k8s.io/yaml"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const disclaimer = `
╭───────────────────────────────────────────────────────────╮
│ DISCLAIMER:                                               │
│                                                           │
│ This tool has copied information about your environment.  │
│ If you are going to register a issue on GitHub, please    │
│ only provide files from the archive you have reviewed     │
│ for sensitive information.                                │
╰───────────────────────────────────────────────────────────╯
`

func generateDirName(config *options.Config) string {
	// Prevent collision with other directories
	nowStr := time.Now().Format("20060102-150405.999-0700-MST")
	var prefix string
	if config.ArchivePrefix != "" {
		prefix = fmt.Sprintf("%s-cilium-bugtool-%s-", config.ArchivePrefix, nowStr)
	} else {
		prefix = fmt.Sprintf("cilium-bugtool-%s-", nowStr)
	}
	return prefix
}

type Bugtool struct {
	// outDir is a temporary directory create to write bugtool dump data prior to archival.
	// Generally this is in the /tmp directory.
	outDir string

	sendArchiveToStdout bool
}

func CreateBugtool(config *options.Config, sd hive.Shutdowner) *Bugtool {
	// Create temporary output directory
	prefix := generateDirName(config)
	sendArchiveToStdout := false
	if config.DumpPath == "-" {
		sendArchiveToStdout = true
		config.DumpPath = options.DefaultDumpPath
	}
	outDir, err := os.MkdirTemp(config.DumpPath, prefix)
	if err != nil {
		sd.Shutdown(hive.ShutdownWithError(fmt.Errorf("Failed to create debug directory %s\n", err)))
	}

	return &Bugtool{
		outDir:              outDir,
		sendArchiveToStdout: sendArchiveToStdout,
	}
}

func main() {
	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Info("Cilium Bugtool ", version.GetCiliumVersion())

	var bugtoolHive = hive.New(
		cell.Provide(configuration.CreateDump),
		cell.Provide(CreateBugtool),
		cell.Config(&options.Config{}),
		cell.Invoke(func(
			config *options.Config,
			bugtoolConfig *options.Config,
			root dump.Task,
			bugtool *Bugtool,
			sd hive.Shutdowner,
		) {
			defer sd.Shutdown()
			if err := config.Validate(); err != nil {
				log.Fatalf("Invalid config: %s", err)
			}

			if config.Debug {
				log.SetLevel(log.DebugLevel)
				log.Debugf("Debug logging enabled")
			}

			ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
			defer cancel()
			if err := root.Validate(context.Background()); err != nil {
				hive.ShutdownWithError(fmt.Errorf("failed to validate config: %w", err))
			}

			// Generate generates config then exists.
			if config.Generate || config.DryRun {
				if config.DryRun {
					log.Info("[Deprecated] use --generate instead")
				}
				log.Info("Generating bugtool config file")
				fd, err := os.Create(config.ConfigFile)
				if err != nil {
					log.Fatalf("Failed to open config file %q: %v", config.ConfigFile, err)
				}
				d, err := yaml.Marshal(root)
				if err != nil {
					log.Fatalf("Failed to encode dump root: %v", err)
				}

				if _, err := fd.Write(d); err != nil {
					log.Fatalf("Failed to encode dump root: %v", err)
				}
				log.Infof("Config file written to %q", config.ConfigFile)
				return
			}

			if config.Wait {
				waitForAgentReady(ctx)
			}

			defer cleanup(config, bugtool.outDir)

			log.Debugf("Running bugtool with %d workers", bugtoolConfig.ParallelWorkers)
			sched := workerpool.New(bugtoolConfig.ParallelWorkers)
			runtime := dump.NewContext(bugtool.outDir, func(s string, f func(context.Context) error) error {
				log.Debugf("Submitting: %s", s)
				return sched.Submit(s, f)
			}, config.ExecTimeout)
			log.Infof("Running scheduled tasks")
			if err := root.Run(ctx, runtime); err != nil {
				sd.Shutdown(hive.ShutdownWithError(err))
			}
			log.Debug("Draining scheduler")
			ts, err := sched.Drain()
			if err != nil {
				sd.Shutdown(hive.ShutdownWithError(err))
			}
			log.Infof("Done, collecting results")
			failed := 0
			for _, t := range ts {
				if t.Err() != nil {
					failed++
					log.Debugf("Scheduled task %q returned an error: %v", t.String(), t.Err())
				}
			}
			if failed > 0 {
				log.Infof("%d scheduled tasks failed", failed)
			}

			runtime.GetResults()

			archive(config, bugtool.outDir)
			fmt.Printf(disclaimer)
		}),
	)

	// Register the flags and parse them.
	bugtoolHive.RegisterFlags(pflag.CommandLine)
	pflag.Parse()

	bugtoolHive.Run()
}

func archive(config *options.Config, dbgDir string) {
	sendArchiveToStdout := config.DumpPath == "-"
	log.Debugf("Attempting to archive of type %q at path %q",
		config.ArchiveType, config.DumpPath)
	if config.Archive {
		switch config.ArchiveType {
		case "gz":
			gzipPath, err := cmd.CreateGzip(dbgDir, sendArchiveToStdout)
			if err != nil {
				log.Fatalf("Failed to create gzip: %v", err)
			}
			// Note: Cilium CLI sysdump depends on this specific formatting
			// by using a regexp to capture the output filename.
			//
			// TODO: Deprecate and remove
			fmt.Printf("GZIP at %s\n", gzipPath)
		case "tar":
			archivePath, err := cmd.CreateArchive(dbgDir, sendArchiveToStdout)
			if err != nil {
				log.Fatalf("Failed to create tar: %v", err)
			}
			fmt.Printf("TAR at %s\n", archivePath)
		}
	} else {
		fmt.Fprintf(os.Stderr, "\nDIRECTORY at %s\n", dbgDir)
	}
}

func cleanup(config *options.Config, dbgDir string) {
	if config.Archive {
		var files []string

		switch config.ArchiveType {
		case "gz":
			files = append(files, dbgDir)
			files = append(files, fmt.Sprintf("%s.tar", dbgDir))
		case "tar":
			files = append(files, dbgDir)
		}

		for _, file := range files {
			if err := os.RemoveAll(file); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to cleanup temporary files %s\n", err)
			}
		}
	}
}

func waitForAgentReady(ctx context.Context) {
	log.Debug("waiting for agent status to be ready")
	for {
		ctx, cancel := context.WithTimeout(ctx, time.Second*20)
		defer cancel()
		err := exec.CommandContext(ctx, "cilium", "status").Run()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				log.Infof("cilium status returned %d, retrying...", ee.ExitCode())
				time.Sleep(time.Second)
				continue
			}
			log.Fatal("encountered unexpected error waiting for agent to be ready: %w", err)
		}
		break
	}
}
