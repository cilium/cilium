// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/lumberjack/v2"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

const (
	defaultHealthHistoryMaxSize    = 5 // MB
	defaultHealthHistoryMaxBackups = 1 // max 2*5=10MB
	healthHistoryFileMode          = 0600
)

type HistoryDir string

type healthHistoryParams struct {
	cell.In

	Lifecycle  cell.Lifecycle
	Logger     *slog.Logger
	HistoryDir HistoryDir
}

type healthHistory struct {
	logger *slog.Logger
	writer *lumberjack.Logger
}

func newHealthHistory(params healthHistoryParams) (*healthHistory, error) {
	if params.HistoryDir == "" {
		return nil, nil
	}
	// Construct a filename tied to the process name to avoid two
	// different kinds of processes from appending to the same history.
	filename := filepath.Join(
		string(params.HistoryDir),
		filepath.Base(os.Args[0])+"-health-history.log")
	h := &healthHistory{
		logger: params.Logger,
		writer: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    defaultHealthHistoryMaxSize,
			MaxBackups: defaultHealthHistoryMaxBackups,
			Compress:   true,
			FileMode:   healthHistoryFileMode,
		},
	}
	params.Lifecycle.Append(h)
	return h, nil
}

func (h *healthHistory) Start(cell.HookContext) error {
	fmt.Fprintf(h.writer, "%s | Started | %s\n", time.Now().UTC().Format(time.RFC3339), version.Version)
	return nil
}

func (h *healthHistory) Stop(cell.HookContext) (err error) {
	if h.writer != nil {
		fmt.Fprintf(h.writer, "%s | Stopped | %s\n", time.Now().UTC().Format(time.RFC3339), version.Version)
		err = h.writer.Close()
		h.writer = nil
	}
	return
}

func (h *healthHistory) observeUpsert(s types.Status) {
	if h == nil {
		return
	}
	if s.Level == types.LevelDegraded {
		h.append(s, false)
	}
}

func (h *healthHistory) observeStopped(s types.Status) {
	if h == nil {
		return
	}
	h.append(s, false)
}

func (h *healthHistory) observeClosed(s types.Status) {
	if h == nil {
		return
	}
	h.append(s, true)
}

func (h *healthHistory) append(status types.Status, closed bool) {
	message := status.Message
	if status.Level == types.LevelStopped && status.Final != "" {
		message = status.Final
	}
	level := status.Level
	if closed {
		level = "Closed(" + level + ")"
	}
	err := ""
	if status.Error != "" {
		err = " | " + status.Error
	}
	fmt.Fprintf(
		h.writer,
		"%s | %-16s | %s: %s%s\n",
		time.Now().UTC().Format(time.RFC3339),
		level,
		status.ID.String(),
		message,
		err,
	)
}

func (h *healthHistory) replay(w io.Writer) error {
	files, err := h.historyFiles()
	if err != nil {
		return err
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		if filepath.Ext(file) == ".gz" {
			var r io.ReadCloser
			if r, err = gzip.NewReader(f); err == nil {
				_, err = io.Copy(w, r)
				r.Close()
			}
		} else {
			_, err = io.Copy(w, f)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *healthHistory) historyFiles() ([]string, error) {
	filename := h.writer.Filename
	dir := filepath.Dir(filename)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading health history directory: %w", err)
	}

	name := filepath.Base(filename)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	prefix := base + "-"

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		entryName := entry.Name()
		if strings.HasPrefix(entryName, prefix) {
			files = append(files, filepath.Join(dir, entryName))
		}
	}
	sort.Strings(files)

	if _, err := os.Stat(filename); err == nil {
		files = append(files, filename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking health history file: %w", err)
	}

	return files, nil
}
