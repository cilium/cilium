// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/workerpool"

	"github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/bugtool/options"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/version"

	"sigs.k8s.io/yaml"

	log "github.com/sirupsen/logrus"
)

type Bugtool struct {
	// outDir is a temporary directory create to write bugtool dump data prior to archival.
	// Generally this is in the /tmp directory.
	outDir string

	sendArchiveToStdout bool
}

func CreateBugtool(config *options.Config) *Bugtool {
	// Create temporary output directory
	prefix := generateDirName(config)
	sendArchiveToStdout := false
	if config.DumpPath == "-" {
		sendArchiveToStdout = true
		config.DumpPath = options.DefaultDumpPath
	}
	outDir, err := os.MkdirTemp(config.DumpPath, prefix)
	if err != nil {
		log.Fatalf("Failed to create debug directory %s", err)
	}

	return &Bugtool{
		outDir:              outDir,
		sendArchiveToStdout: sendArchiveToStdout,
	}
}

func (bugtool *Bugtool) runTool(ctx context.Context, config *options.Config, root dump.Task) {
	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Info("Cilium Bugtool ", version.GetCiliumVersion())

	if err := config.Validate(); err != nil {
		log.Fatalf("Invalid config: %s", err)
	}

	if config.Debug {
		log.SetLevel(log.DebugLevel)
		log.Debugf("Debug logging enabled")
	}

	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
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
		if err := waitForAgentReady(ctx, config.WaitTimeout); err != nil {
			log.Fatalf("Failed to wait for agent: %v", err)
		}
	}

	defer cleanup(bugtool.outDir, config.Archive)

	log.Debugf("Running bugtool with %d workers", config.ParallelWorkers)
	sched := workerpool.New(config.ParallelWorkers)
	runtime := dump.NewContext(bugtool.outDir, func(s string, f func(context.Context) error) error {
		log.Debugf("Submitting: %s", s)
		return sched.Submit(s, f)
	})
	log.Infof("Running scheduled tasks")
	if err := root.Run(ctx, runtime); err != nil {
		log.WithError(err).Fatal("Failed to run dump")
	}
	log.Debug("Draining scheduler")
	ts, err := sched.Drain()
	if err != nil {
		log.WithError(err).Fatal("Failed to schedule dump tasks")
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

	createArchive(config, bugtool.outDir)
	fmt.Print(disclaimer)
}

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

func createArchive(config *options.Config, dbgDir string) {
	sendArchiveToStdout := config.DumpPath == "-"
	log.Debugf("Attempting to archive of type %q at path %q",
		config.ArchiveType, config.DumpPath)
	if config.Archive {
		switch config.ArchiveType {
		case "gz":
			gzipPath, err := CreateGzip(dbgDir, sendArchiveToStdout)
			if err != nil {
				log.Fatalf("Failed to create gzip: %v", err)
			}
			// Note: Cilium CLI sysdump depends on this specific formatting
			// by using a regexp to capture the output filename.
			//
			// TODO: Deprecate and remove
			fmt.Printf("GZIP at %s\n", gzipPath)
		case "tar":
			archivePath, err := CreateArchive(dbgDir, sendArchiveToStdout)
			if err != nil {
				log.Fatalf("Failed to create tar: %v", err)
			}
			fmt.Printf("TAR at %s\n", archivePath)
		}
	} else {
		fmt.Fprintf(os.Stderr, "\nDIRECTORY at %s\n", dbgDir)
	}
}

func waitForAgentReady(ctx context.Context, waitTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	log.Debug("waiting for agent status to be ready")
	for {
		if err := exec.CommandContext(ctx, "cilium", "status").Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				log.Infof("cilium status returned %d, retrying...", ee.ExitCode())
				time.Sleep(time.Second)
				continue
			}
			return fmt.Errorf("encountered unexpected error waiting for agent to be ready: %w", err)
		}
		break
	}
	return nil
}
