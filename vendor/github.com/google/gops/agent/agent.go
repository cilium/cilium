// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package agent provides hooks programs can register to retrieve
// diagnostics data by using gops.
package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	gosignal "os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gops/internal"
	"github.com/google/gops/signal"
)

const defaultAddr = "127.0.0.1:0"

var (
	mu       sync.Mutex
	portfile string
	listener net.Listener

	units = []string{" bytes", "KB", "MB", "GB", "TB", "PB"}
)

// Options allows configuring the started agent.
type Options struct {
	// Addr is the host:port the agent will be listening at.
	// Optional.
	Addr string

	// ConfigDir is the directory to store the configuration file,
	// PID of the gops process, filename, port as well as content.
	// Optional.
	ConfigDir string

	// ShutdownCleanup automatically cleans up resources if the
	// running process receives an interrupt. Otherwise, users
	// can call Close before shutting down.
	// Optional.
	ShutdownCleanup bool

	// ReuseSocketAddrAndPort determines whether the SO_REUSEADDR and
	// SO_REUSEPORT socket options should be set on the listening socket of
	// the agent. This option is only effective on unix-like OSes and if
	// Addr is set to a fixed host:port.
	// Optional.
	ReuseSocketAddrAndPort bool
}

// Listen starts the gops agent on a host process. Once agent started, users
// can use the advanced gops features. The agent will listen to Interrupt
// signals and exit the process, if you need to perform further work on the
// Interrupt signal use the options parameter to configure the agent
// accordingly.
//
// Note: The agent exposes an endpoint via a TCP connection that can be used by
// any program on the system. Review your security requirements before starting
// the agent.
func Listen(opts Options) error {
	mu.Lock()
	defer mu.Unlock()

	if portfile != "" {
		return fmt.Errorf("gops: agent already listening at: %v", listener.Addr())
	}

	// new
	gopsdir := opts.ConfigDir
	if gopsdir == "" {
		cfgDir, err := internal.ConfigDir()
		if err != nil {
			return err
		}
		gopsdir = cfgDir
	}

	err := os.MkdirAll(gopsdir, os.ModePerm)
	if err != nil {
		return err
	}
	if opts.ShutdownCleanup {
		gracefulShutdown()
	}

	addr := opts.Addr
	if addr == "" {
		addr = defaultAddr
	}
	var lc net.ListenConfig
	if opts.ReuseSocketAddrAndPort {
		lc.Control = setReuseAddrAndPortSockopts
	}
	listener, err = lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	portfile = filepath.Join(gopsdir, strconv.Itoa(os.Getpid()))
	err = ioutil.WriteFile(portfile, []byte(strconv.Itoa(port)), os.ModePerm)
	if err != nil {
		return err
	}

	go listen(listener)
	return nil
}

func listen(l net.Listener) {
	buf := make([]byte, 1)
	for {
		fd, err := l.Accept()
		if err != nil {
			// No great way to check for this, see https://golang.org/issues/4373.
			if !strings.Contains(err.Error(), "use of closed network connection") {
				fmt.Fprintf(os.Stderr, "gops: %v\n", err)
			}
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				break
			}
			continue
		}
		if _, err := fd.Read(buf); err != nil {
			fmt.Fprintf(os.Stderr, "gops: %v\n", err)
			continue
		}
		if err := handle(fd, buf); err != nil {
			fmt.Fprintf(os.Stderr, "gops: %v\n", err)
			continue
		}
		fd.Close()
	}
}

func gracefulShutdown() {
	c := make(chan os.Signal, 1)
	gosignal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		// cleanup the socket on shutdown.
		sig := <-c
		Close()
		ret := 1
		if sig == syscall.SIGTERM {
			ret = 0
		}
		os.Exit(ret)
	}()
}

// Close closes the agent, removing temporary files and closing the TCP listener.
// If no agent is listening, Close does nothing.
func Close() {
	mu.Lock()
	defer mu.Unlock()

	if portfile != "" {
		os.Remove(portfile)
		portfile = ""
	}
	if listener != nil {
		listener.Close()
	}
}

func formatBytes(val uint64) string {
	var i int
	var target uint64
	for i = range units {
		target = 1 << uint(10*(i+1))
		if val < target {
			break
		}
	}
	if i > 0 {
		return fmt.Sprintf("%0.2f%s (%d bytes)", float64(val)/(float64(target)/1024), units[i], val)
	}
	return fmt.Sprintf("%d bytes", val)
}

func handle(conn io.ReadWriter, msg []byte) error {
	switch msg[0] {
	case signal.StackTrace:
		return pprof.Lookup("goroutine").WriteTo(conn, 2)
	case signal.GC:
		runtime.GC()
		_, err := conn.Write([]byte("ok"))
		return err
	case signal.MemStats:
		var s runtime.MemStats
		runtime.ReadMemStats(&s)
		fmt.Fprintf(conn, "alloc: %v\n", formatBytes(s.Alloc))
		fmt.Fprintf(conn, "total-alloc: %v\n", formatBytes(s.TotalAlloc))
		fmt.Fprintf(conn, "sys: %v\n", formatBytes(s.Sys))
		fmt.Fprintf(conn, "lookups: %v\n", s.Lookups)
		fmt.Fprintf(conn, "mallocs: %v\n", s.Mallocs)
		fmt.Fprintf(conn, "frees: %v\n", s.Frees)
		fmt.Fprintf(conn, "heap-alloc: %v\n", formatBytes(s.HeapAlloc))
		fmt.Fprintf(conn, "heap-sys: %v\n", formatBytes(s.HeapSys))
		fmt.Fprintf(conn, "heap-idle: %v\n", formatBytes(s.HeapIdle))
		fmt.Fprintf(conn, "heap-in-use: %v\n", formatBytes(s.HeapInuse))
		fmt.Fprintf(conn, "heap-released: %v\n", formatBytes(s.HeapReleased))
		fmt.Fprintf(conn, "heap-objects: %v\n", s.HeapObjects)
		fmt.Fprintf(conn, "stack-in-use: %v\n", formatBytes(s.StackInuse))
		fmt.Fprintf(conn, "stack-sys: %v\n", formatBytes(s.StackSys))
		fmt.Fprintf(conn, "stack-mspan-inuse: %v\n", formatBytes(s.MSpanInuse))
		fmt.Fprintf(conn, "stack-mspan-sys: %v\n", formatBytes(s.MSpanSys))
		fmt.Fprintf(conn, "stack-mcache-inuse: %v\n", formatBytes(s.MCacheInuse))
		fmt.Fprintf(conn, "stack-mcache-sys: %v\n", formatBytes(s.MCacheSys))
		fmt.Fprintf(conn, "other-sys: %v\n", formatBytes(s.OtherSys))
		fmt.Fprintf(conn, "gc-sys: %v\n", formatBytes(s.GCSys))
		fmt.Fprintf(conn, "next-gc: when heap-alloc >= %v\n", formatBytes(s.NextGC))
		lastGC := "-"
		if s.LastGC != 0 {
			lastGC = fmt.Sprint(time.Unix(0, int64(s.LastGC)))
		}
		fmt.Fprintf(conn, "last-gc: %v\n", lastGC)
		fmt.Fprintf(conn, "gc-pause-total: %v\n", time.Duration(s.PauseTotalNs))
		fmt.Fprintf(conn, "gc-pause: %v\n", s.PauseNs[(s.NumGC+255)%256])
		fmt.Fprintf(conn, "gc-pause-end: %v\n", s.PauseEnd[(s.NumGC+255)%256])
		fmt.Fprintf(conn, "num-gc: %v\n", s.NumGC)
		fmt.Fprintf(conn, "num-forced-gc: %v\n", s.NumForcedGC)
		fmt.Fprintf(conn, "gc-cpu-fraction: %v\n", s.GCCPUFraction)
		fmt.Fprintf(conn, "enable-gc: %v\n", s.EnableGC)
		fmt.Fprintf(conn, "debug-gc: %v\n", s.DebugGC)
	case signal.Version:
		fmt.Fprintf(conn, "%v\n", runtime.Version())
	case signal.HeapProfile:
		return pprof.WriteHeapProfile(conn)
	case signal.CPUProfile:
		if err := pprof.StartCPUProfile(conn); err != nil {
			return err
		}
		time.Sleep(30 * time.Second)
		pprof.StopCPUProfile()
	case signal.Stats:
		fmt.Fprintf(conn, "goroutines: %v\n", runtime.NumGoroutine())
		fmt.Fprintf(conn, "OS threads: %v\n", pprof.Lookup("threadcreate").Count())
		fmt.Fprintf(conn, "GOMAXPROCS: %v\n", runtime.GOMAXPROCS(0))
		fmt.Fprintf(conn, "num CPU: %v\n", runtime.NumCPU())
	case signal.BinaryDump:
		path, err := os.Executable()
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = bufio.NewReader(f).WriteTo(conn)
		return err
	case signal.Trace:
		if err := trace.Start(conn); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
		trace.Stop()
	case signal.SetGCPercent:
		perc, err := binary.ReadVarint(bufio.NewReader(conn))
		if err != nil {
			return err
		}
		fmt.Fprintf(conn, "New GC percent set to %v. Previous value was %v.\n", perc, debug.SetGCPercent(int(perc)))
	}
	return nil
}
