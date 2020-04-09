// Copyright 2017-2020 Authors of Hubble
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
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/cilium/hubble/cmd/observe"
	"github.com/cilium/hubble/cmd/status"
	"github.com/cilium/hubble/cmd/version"
	"github.com/cilium/hubble/pkg"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile                        string
	cpuprofile, memprofile         string
	cpuprofileFile, memprofileFile *os.File
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "hubble",
	Short:         "CLI",
	Long:          `Hubble is a utility to observe and inspect recent Cilium routed traffic in a cluster.`,
	SilenceErrors: true, // this is being handled in main, no need to duplicate error messages
	SilenceUsage:  true,
	Version:       pkg.Version,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return pprofInit()
	},
	PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
		return pprofTearDown()
	},
}

func pprofInit() error {
	var err error
	if cpuprofile != "" {
		cpuprofileFile, err = os.Create(cpuprofile)
		if err != nil {
			return fmt.Errorf("failed to create cpu profile: %v", err)
		}
		pprof.StartCPUProfile(cpuprofileFile)
	}
	if memprofile != "" {
		memprofileFile, err = os.Create(memprofile)
		if err != nil {
			return fmt.Errorf("failed to create memory profile: %v", err)
		}
	}
	return nil
}

func pprofTearDown() error {
	if cpuprofileFile != nil {
		pprof.StopCPUProfile()
		cpuprofileFile.Close()
	}
	if memprofileFile != nil {
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memprofileFile); err != nil {
			return fmt.Errorf("failed to write memory profile: %v", err)
		}
		memprofileFile.Close()
	}
	return nil
}

// Execute adds all child commands to the root command sets flags
// appropriately. This is called by main.main(). It only needs to happen once
// to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.hubble.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")
	viper.BindPFlags(flags)
	rootCmd.AddCommand(newCmdCompletion(os.Stdout))
	rootCmd.SetErr(os.Stderr)

	rootCmd.PersistentFlags().StringVar(&cpuprofile,
		"cpuprofile", "", "Enable CPU profiling",
	)
	rootCmd.PersistentFlags().StringVar(&memprofile,
		"memprofile", "", "Enable memory profiling",
	)
	rootCmd.PersistentFlags().Lookup("cpuprofile").Hidden = true
	rootCmd.PersistentFlags().Lookup("memprofile").Hidden = true

	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")

	// initialize all subcommands
	rootCmd.AddCommand(observe.New())
	rootCmd.AddCommand(version.New())
	rootCmd.AddCommand(status.New())
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("hubble")
	viper.SetConfigName(".hubble") // name of config file (without extension)
	viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

const copyRightHeader = `
# Copyright 2019 Authors of Hubble
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
`

var (
	completionExample = `
# Installing bash completion on macOS using homebrew
## If running Bash 3.2 included with macOS
	brew install bash-completion
## or, if running Bash 4.1+
	brew install bash-completion@2
## afterwards you only need to run
	hubble completion bash > $(brew --prefix)/etc/bash_completion.d/hubble


# Installing bash completion on Linux
## Load the hubble completion code for bash into the current shell
	source <(hubble completion bash)
## Write bash completion code to a file and source if from .bash_profile
	hubble completion bash > ~/.hubble/completion.bash.inc
	printf "
	  # Hubble shell completion
	  source '$HOME/.hubble/completion.bash.inc'
	  " >> $HOME/.bash_profile
	source $HOME/.bash_profile

# Installing zsh completion on Linux/macOS
## Load the hubble completion code for zsh into the current shell
        source <(hubble completion zsh)
## Write zsh completion code to a file and source if from .zshrc
        hubble completion zsh > ~/.hubble/completion.zsh.inc
        printf "
          # Hubble shell completion
          source '$HOME/.hubble/completion.zsh.inc'
          " >> $HOME/.zshrc
        source $HOME/.zshrc`
)

func newCmdCompletion(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "completion [shell]",
		Short:   "Output shell completion code",
		Long:    ``,
		Example: completionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompletion(out, cmd, args)
		},
		ValidArgs: []string{"bash", "zsh"},
	}

	return cmd
}

func runCompletion(out io.Writer, cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("too many arguments; expected only the shell type")
	}
	if _, err := out.Write([]byte(copyRightHeader)); err != nil {
		return err
	}

	if len(args) == 0 {
		return cmd.Parent().GenBashCompletion(out)
	}

	switch args[0] {
	case "bash":
		return cmd.Parent().GenBashCompletion(out)
	case "zsh":
		return cmd.Parent().GenZshCompletion(out)
	}

	return fmt.Errorf("unsupported shell type: %s", args[0])
}
