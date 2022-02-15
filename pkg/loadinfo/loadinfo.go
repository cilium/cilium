// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadinfo

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
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

// LogCurrentSystemLoad logs the current system load and lists all processes
// consuming more than cpuWatermark of the CPU
func LogCurrentSystemLoad(logFunc LogFunc) {
	loadInfo, err := load.Avg()
	if err == nil {
		logFunc("Load 1-min: %.2f 5-min: %.2f 15min: %.2f",
			loadInfo.Load1, loadInfo.Load5, loadInfo.Load15)
	}

	memInfo, err := mem.VirtualMemory()
	if err == nil && memInfo != nil {
		logFunc("Memory: Total: %d Used: %d (%.2f%%) Free: %d Buffers: %d Cached: %d",
			toMB(memInfo.Total), toMB(memInfo.Used), memInfo.UsedPercent, toMB(memInfo.Free), toMB(memInfo.Buffers), toMB(memInfo.Cached))
	}

	swapInfo, err := mem.SwapMemory()
	if err == nil && swapInfo != nil {
		logFunc("Swap: Total: %d Used: %d (%.2f%%) Free: %d",
			toMB(swapInfo.Total), toMB(swapInfo.Used), swapInfo.UsedPercent, toMB(swapInfo.Free))
	}

	procs, err := process.Processes()
	if err == nil {
		for _, p := range procs {
			cpuPercent, _ := p.CPUPercent()
			if cpuPercent > cpuWatermark {
				name, _ := p.Name()
				status, _ := p.Status()
				memPercent, _ := p.MemoryPercent()
				cmdline, _ := p.Cmdline()

				memExt := ""
				if memInfo, err := p.MemoryInfo(); memInfo != nil && err == nil {
					memExt = fmt.Sprintf("RSS: %d VMS: %d Data: %d Stack: %d Locked: %d Swap: %d",
						toMB(memInfo.RSS), toMB(memInfo.VMS), toMB(memInfo.Data),
						toMB(memInfo.Stack), toMB(memInfo.Locked), toMB(memInfo.Swap))
				}

				logFunc("NAME %s STATUS %s PID %d CPU: %.2f%% MEM: %.2f%% CMDLINE: %s MEM-EXT: %s",
					name, status, p.Pid, cpuPercent, memPercent, cmdline, memExt)
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
