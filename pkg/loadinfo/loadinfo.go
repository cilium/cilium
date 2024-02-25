// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadinfo

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mackerelio/go-osstat/loadavg"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// backgroundInterval is the interval in which system load information is logged
	backgroundInterval = 5 * time.Second

	// cpuWatermark is the minimum percentage of CPU to have a process
	// listed in the log
	cpuWatermark = 1.0
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "loadinfo")

// LogFunc is the function to used to log the system load
type LogFunc func(format string, args ...interface{})

func toMB(total uint64) uint64 {
	return total / 1024 / 1024
}

func toPercent(part uint64, total uint64) float64 {
	return float64(part) / float64(total) * 100
}

func pids() (pids []int, err error) {
	//scan /proc/*/exe to find all active processes
	matches, err := filepath.Glob("/proc/[0-9]*/exe")
	if err != nil {
		return nil, err
	}

	pids = []int{}
	for _, file := range matches {
		//extract the pid from the path
		pid := filepath.Base(filepath.Dir(file))
		ipid, _ := strconv.Atoi(pid)
		pids = append(pids, ipid)
	}

	return
}

func cpuPercent(stat procfs.ProcStat) float64 {
	starttime, err := stat.StartTime()
	if err != nil {
		return 0
	}

	// calculate the percentage of CPU used since the process started
	return (stat.CPUTime() / (float64(time.Now().Unix()) - starttime) * 100)
}

// LogCurrentSystemLoad logs the current system load and lists all processes
// consuming more than cpuWatermark of the CPU
func LogCurrentSystemLoad(logFunc LogFunc) {
	loadInfo, err := loadavg.Get()
	if err == nil {
		logFunc("Load 1-min: %.2f 5-min: %.2f 15min: %.2f",
			loadInfo.Loadavg1, loadInfo.Loadavg5, loadInfo.Loadavg15)
	}

	memInfo, err := memory.Get()
	if err == nil {
		logFunc("Memory: Total: %d Used: %d (%.2f%%) Free: %d Buffers: %d Cached: %d",
			toMB(memInfo.Total), toMB(memInfo.Used), toPercent(memInfo.Used, memInfo.Total), toMB(memInfo.Free), toMB(memInfo.Buffers), toMB(memInfo.Cached))

		logFunc("Swap: Total: %d Used: %d (%.2f%%) Free: %d",
			toMB(memInfo.SwapTotal), toMB(memInfo.SwapUsed), toPercent(memInfo.SwapUsed, memInfo.SwapTotal), toMB(memInfo.SwapFree))
	}

	pids, err := pids()
	if err == nil {
		for _, pid := range pids {
			procfs, err := procfs.NewProc(pid)
			if err != nil {
				// Process might have exited in the meantime
				continue
			}

			stat, err := procfs.Stat()
			if err != nil {
				// Process might have exited in the meantime
				continue
			}

			psStatus, err := procfs.NewStatus()
			if err != nil {
				continue
			}

			cpuPercent := cpuPercent(stat)
			if cpuPercent > cpuWatermark {
				name, _ := procfs.Comm()
				status := stat.State
				memPercent := float64(psStatus.VmRSS) * 100 / float64(memInfo.Total)
				cmdline, _ := procfs.CmdLine()

				memExt := fmt.Sprintf("RSS: %d VMS: %d Data: %d Stack: %d Locked: %d Swap: %d",
					toMB(psStatus.VmRSS), toMB(psStatus.VmSize), toMB(psStatus.VmData),
					toMB(psStatus.VmStk), toMB(psStatus.VmLck), toMB(psStatus.VmSwap))

				logFunc("NAME %s STATUS %s PID %d CPU: %.2f%% MEM: %.2f%% CMDLINE: %s MEM-EXT: %s",
					name, status, pid, cpuPercent, memPercent, cmdline, memExt)
			}
		}
	}
}

// LogPeriodicSystemLoad logs the system load in the interval specified until
// the given ctx is canceled.
func LogPeriodicSystemLoad(ctx context.Context, logFunc LogFunc, interval time.Duration) {
	go func() {
		LogCurrentSystemLoad(logFunc)

		timer, timerDone := inctimer.New()
		defer timerDone()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.After(interval):
				LogCurrentSystemLoad(logFunc)
			}
		}
	}()
}

// StartBackgroundLogger starts background logging
func StartBackgroundLogger() {
	LogPeriodicSystemLoad(context.Background(), log.WithFields(logrus.Fields{"type": "background"}).Debugf, backgroundInterval)
}
