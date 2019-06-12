// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/cilium/pkg/health/probe/responder"

	flag "github.com/spf13/pflag"
)

func removePidfile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "failed to remove pidfile: %s\n", err.Error())
	}
}

func writePidfile(path string) error {
	pid := os.Getpid()
	pidBytes := []byte(strconv.Itoa(pid) + "\n")
	return ioutil.WriteFile(path, pidBytes, 0660)
}

func cancelOnSignal(cancel context.CancelFunc) {
	go func() {
		defer cancel()

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		<-c
	}()
}

func main() {
	var (
		pidfile string
		listen  int
	)
	flag.StringVar(&pidfile, "pidfile", "", "Write pid to the specified file")
	flag.IntVar(&listen, "listen", 4240, "Port on which the responder listens")
	flag.Parse()

	// Shutdown gracefully to halt server and remove pidfile
	ctx, cancel := context.WithCancel(context.Background())
	cancelOnSignal(cancel)

	srv := responder.NewServer(listen)
	defer srv.Shutdown()
	go func() {
		if err := srv.Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "error while listening: %s\n", err.Error())
			cancel()
		}
	}()

	if pidfile != "" {
		defer removePidfile(pidfile)
		if err := writePidfile(pidfile); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write pidfile: %s: %s\n", pidfile, err.Error())
			os.Exit(-1)
		}
	}

	<-ctx.Done()
}
