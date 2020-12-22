// Copyright 2017 Authors of Cilium
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

	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/components"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	client  *clientPkg.Client
	log     = logrus.New()
	verbose = false
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cilium",
	Short: "CLI",
	Long:  `CLI for interacting with the local Cilium Agent`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	if components.IsCiliumAgent() {
		return
	}

	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cilium.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.StringP("host", "H", "", "URI to server-side API")
	viper.BindPFlags(flags)
	rootCmd.AddCommand(newCmdCompletion(os.Stdout))
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("cilium")
	viper.SetConfigName(".cilium") // name of config file (without extension)
	viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	if viper.GetBool("debug") {
		log.Level = logrus.DebugLevel
	} else {
		log.Level = logrus.InfoLevel
	}

	if cl, err := clientPkg.NewClient(viper.GetString("host")); err != nil {
		Fatalf("Error while creating client: %s\n", err)
	} else {
		client = cl
	}
}

const copyRightHeader = `# Copyright 2017-2020 Authors of Cilium
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
	cilium completion bash > $(brew --prefix)/etc/bash_completion.d/cilium


# Installing bash completion on Linux
## Load the cilium completion code for bash into the current shell
	source <(cilium completion bash)
## Write bash completion code to a file and source if from .bash_profile
	cilium completion bash > ~/.cilium/completion.bash.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.bash.inc'
	  " >> $HOME/.bash_profile
	source $HOME/.bash_profile


# Installing zsh completion on Linux/macOS
## Load the cilium completion code for zsh into the current shell
	source <(cilium completion zsh)
## Write zsh completion code to a file and source if from .zshrc
	cilium completion zsh > ~/.cilium/completion.zsh.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.zsh.inc'
	  " >> $HOME/.zshrc
	source $HOME/.zshrc

# Installing fish completion on Linux/macOS
## Write fish completion code to fish specific location
	cilium completion fish > ~/.config/fish/completions/cilium.fish
`
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
		ValidArgs: []string{"bash", "zsh", "fish"},
	}

	return cmd
}

func runCompletion(out io.Writer, cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("too many arguments; expected only the shell type: %s", args)
	}

	if len(args) == 0 || args[0] == "bash" {
		if _, err := out.Write([]byte(copyRightHeader)); err != nil {
			return err
		}
		return cmd.Root().GenBashCompletion(out)
	}
	if args[0] == "zsh" {
		if _, err := out.Write([]byte(copyRightHeader)); err != nil {
			return err
		}
		return cmd.Root().GenZshCompletion(out)
	}
	if args[0] == "fish" {
		if _, err := out.Write([]byte(copyRightHeader)); err != nil {
			return err
		}
		return cmd.Root().GenFishCompletion(out, true)
	}
	return fmt.Errorf("unsupported shell: %s", args[0])
}
