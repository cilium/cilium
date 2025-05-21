// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"

	"k8s.io/klog/v2"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var klogErrorOverrides = []logLevelOverride{
	{
		// TODO: We can drop the misspelled case here once client-go version is bumped to include:
		//	https://github.com/kubernetes/client-go/commit/ae43527480ee9d8750fbcde3d403363873fd3d89
		matcher:     regexp.MustCompile("Failed to update lock (optimitically|optimistically).*falling back to slow path"),
		targetLevel: slog.LevelInfo,
	},
}

func initializeKLog(logger *slog.Logger) error {
	log := logger.With(logfields.LogSubsys, "klog")

	// Create a new flag set and set error handler
	klogFlags := flag.NewFlagSet("cilium", flag.ExitOnError)

	// Make sure that klog logging variables are initialized so that we can
	// update them from this file.
	klog.InitFlags(klogFlags)

	// Make sure klog does not log to stderr as we want it to control the output
	// of klog so we want klog to log the errors to each writer of each level.
	klogFlags.Set("logtostderr", "false")

	// We don't need all headers because logrus will already print them if
	// necessary.
	klogFlags.Set("skip_headers", "true")

	infoWriter, err := severityOverrideWriter(slog.LevelInfo, log, nil)
	if err != nil {
		return fmt.Errorf("failed to setup klog error writer: %w", err)
	}
	warnWriter, err := severityOverrideWriter(slog.LevelWarn, log, nil)
	if err != nil {
		return fmt.Errorf("failed to setup klog error writer: %w", err)
	}
	errWriter, err := severityOverrideWriter(slog.LevelError, log, klogErrorOverrides)
	if err != nil {
		return fmt.Errorf("failed to setup klog error writer: %w", err)
	}
	fatalWriter, err := severityOverrideWriter(LevelPanic, log, nil)
	if err != nil {
		return fmt.Errorf("failed to setup klog error writer: %w", err)
	}

	klog.SetOutputBySeverity("INFO", infoWriter)
	klog.SetOutputBySeverity("WARNING", warnWriter)
	klog.SetOutputBySeverity("ERROR", errWriter)
	klog.SetOutputBySeverity("FATAL", fatalWriter)

	// Do not repeat log messages on all severities in klog
	klogFlags.Set("one_output", "true")

	return nil
}

type logLevelOverride struct {
	matcher     *regexp.Regexp
	targetLevel slog.Level
}

func levelToPrintFunc(log *slog.Logger, level slog.Level) (func(msg string, args ...any), error) {
	var printFunc func(msg string, args ...any)
	switch level {
	case slog.LevelInfo:
		printFunc = log.Info
	case slog.LevelWarn:
		printFunc = log.Warn
	case slog.LevelError:
		printFunc = log.Error
	case LevelPanic:
		printFunc = func(msg string, args ...any) {
			Panic(log, msg, args)
		}
	case LevelFatal:
		printFunc = func(msg string, args ...any) {
			Fatal(log, msg, args)
		}
	default:
		return nil, fmt.Errorf("unsupported log level %q", level)
	}
	return printFunc, nil
}

func severityOverrideWriter(level slog.Level, log *slog.Logger, overrides []logLevelOverride) (*io.PipeWriter, error) {
	printFunc, err := levelToPrintFunc(log, level)
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()

	for _, override := range overrides {
		_, err := levelToPrintFunc(log, override.targetLevel)
		if err != nil {
			return nil, fmt.Errorf("failed to validate klog matcher level overrides (%s -> %s): %w",
				override.matcher.String(), level, err)
		}
	}
	go writerScanner(log, reader, printFunc, overrides)
	return writer, nil
}

// writerScanner scans the input from the reader and writes it to the appropriate
// log print func.
// In cases where the log message is overridden, that will be emitted via the specified
// target log level logger function.
//
// Based on code from logrus WriterLevel implementation [1]
//
// [1] https://github.com/sirupsen/logrus/blob/v1.9.3/writer.go#L66-L97
func writerScanner(
	entry *slog.Logger,
	reader *io.PipeReader,
	defaultPrintFunc func(msg string, args ...any),
	overrides []logLevelOverride) {

	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	// Set the buffer size to the maximum token size to avoid buffer overflows
	scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	// Define a split function to split the input into chunks of up to 64KB
	chunkSize := bufio.MaxScanTokenSize // 64KB
	splitFunc := func(data []byte, atEOF bool) (int, []byte, error) {
		if len(data) >= chunkSize {
			return chunkSize, data[:chunkSize], nil
		}

		return bufio.ScanLines(data, atEOF)
	}

	// Use the custom split function to split the input
	scanner.Split(splitFunc)

	// Scan the input and write it to the logger using the specified print function
	for scanner.Scan() {
		line := scanner.Text()
		matched := false
		for _, override := range overrides {
			printFn, err := levelToPrintFunc(entry, override.targetLevel)
			if err != nil {
				entry.Error("BUG: failed to get printer for klog override matcher",
					logfields.Error, err,
					logfields.Matcher, override.matcher,
				)
				continue
			}
			if override.matcher.FindString(line) != "" {
				printFn(strings.TrimRight(line, "\r\n"))
				matched = true
				break
			}
		}
		if !matched {
			defaultPrintFunc(strings.TrimRight(scanner.Text(), "\r\n"))
		}
	}

	if err := scanner.Err(); err != nil {
		entry.Error("klog slog override scanner stopped scanning with an error. "+
			"This may mean that k8s client-go logs will no longer be emitted", logfields.Error, err)
	}
}
