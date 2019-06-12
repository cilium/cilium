// Copyright 2017-2018 Authors of Cilium
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

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/api"
	clientPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	serverPkg "github.com/cilium/cilium/pkg/health/server"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
)

const targetName = "cilium-health"

var (
	cfgFile   string
	client    *clientPkg.Client
	cmdRefDir string
	server    *serverPkg.Server
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, targetName)
	logOpts   = make(map[string]string)
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   targetName,
	Short: "Cilium Health Agent",
	Long:  `Agent for hosting and querying the Cilium health status API`,
	Run:   run,
}

// Fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable
func Fatalf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(-1)
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.BoolP("daemon", "d", false, "Run as a daemon")
	flags.StringP("host", "H", "", "URI to cilium-health server API")
	flags.StringP("cilium", "c", "", "URI to Cilium server API")
	flags.UintP("interval", "i", 60, "Interval (in seconds) for periodic connectivity probes")
	flags.StringSlice("log-driver", []string{}, "Logging endpoints to use for example syslog")
	flags.Var(option.NewNamedMapOptions("log-opts", &logOpts, nil),
		"log-opt", "Log driver options for cilium-health")
	viper.BindPFlags(flags)

	flags.StringVar(&cmdRefDir, "cmdref", "", "Path to cmdref output directory")
	flags.MarkHidden("cmdref")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetEnvPrefix("cilium")
	viper.SetConfigName(".cilium-health") // name of config file (without extension)
	viper.AddConfigPath("$HOME")          // adding home directory as first search path

	if viper.GetBool("debug") {
		log.Level = logrus.DebugLevel
	} else {
		log.Level = logrus.InfoLevel
	}

	if viper.GetBool("daemon") {
		config := serverPkg.Config{
			CiliumURI:     viper.GetString("cilium"),
			Debug:         viper.GetBool("debug"),
			ProbeInterval: time.Duration(viper.GetInt("interval")) * time.Second,
			ProbeDeadline: time.Second,
		}
		if srv, err := serverPkg.NewServer(config); err != nil {
			Fatalf("Error while creating server: %s\n", err)
		} else {
			server = srv
		}
	} else if cl, err := clientPkg.NewClient(viper.GetString("host")); err != nil {
		Fatalf("Error while creating client: %s\n", err)
	} else {
		client = cl
	}
}

func runServer() {
	common.RequireRootPrivilege(targetName)

	// Open socket for using gops to get stacktraces of the daemon.
	if err := gops.Listen(gops.Options{}); err != nil {
		log.WithError(err).Fatal("unable to start gops")
	}

	// When the unix socket is made available, set its permissions.
	go func() {
		scopedLog := log.WithField(logfields.Path, defaults.SockPath)
		for {
			_, err := os.Stat(defaults.SockPath)
			if err == nil {
				break
			}
			scopedLog.WithError(err).Debugf("Cannot find socket")
			time.Sleep(1 * time.Second)
		}
		if err := api.SetDefaultPermissions(defaults.SockPath); err != nil {
			scopedLog.WithError(err).Fatal("Cannot set default permissions on socket")
		}
	}()

	defer server.Shutdown()
	if err := server.Serve(); err != nil {
		log.WithError(err).Error("Failed to serve cilium-health API")
	}
}

func run(cmd *cobra.Command, args []string) {
	// Logging should always be bootstrapped first. Do not add any code above this!
	logging.SetupLogging(viper.GetStringSlice("log-driver"), logOpts, "cilium-health", viper.GetBool("debug"))

	if cmdRefDir != "" {
		// Remove the line 'Auto generated by spf13/cobra on ...'
		cmd.DisableAutoGenTag = true
		if err := doc.GenMarkdownTreeCustom(cmd, cmdRefDir, filePrepend, linkHandler); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if viper.GetBool("daemon") {
		runServer()
	} else {
		cmd.Help()
	}
}

func linkHandler(s string) string {
	// The generated files have a 'See also' section but the URL's are
	// hardcoded to use Markdown but we only want / have them in HTML
	// later.
	return strings.Replace(s, ".md", ".html", 1)
}

func filePrepend(s string) string {
	// Prepend a HTML comment that this file is autogenerated. So that
	// users are warned before fixing issues in the Markdown files.  Should
	// never show up on the web.
	return fmt.Sprintf("%s\n\n", "<!-- This file was autogenerated via cilium-agent --cmdref, do not edit manually-->")
}
