// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/components"
)

var (
	vp = viper.New()

	cfgFile string
	client  *clientPkg.Client
	log     = logrus.New()
	verbose = false
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "cilium-dbg",
	Short: "CLI",
	Long:  `CLI for interacting with the local Cilium Agent`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	if components.IsCiliumAgent() {
		return
	}

	cobra.OnInitialize(initConfig)
	flags := RootCmd.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "", "Config file (default is $HOME/.cilium.yaml)")
	flags.BoolP("debug", "D", false, "Enable debug messages")
	flags.StringP("host", "H", "", "URI to server-side API")
	vp.BindPFlags(flags)
	RootCmd.AddCommand(newCmdCompletion(os.Stdout))
	RootCmd.SetOut(os.Stdout)
	RootCmd.SetErr(os.Stderr)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		vp.SetConfigFile(cfgFile)
	}

	vp.SetEnvPrefix("cilium")
	vp.SetConfigName(".cilium") // name of config file (without extension)
	vp.AddConfigPath("$HOME")   // adding home directory as first search path
	vp.AutomaticEnv()           // read in environment variables that match

	// If a config file is found, read it in.
	if err := vp.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", vp.ConfigFileUsed())
	}

	if vp.GetBool("debug") {
		log.Level = logrus.DebugLevel
	} else {
		log.Level = logrus.InfoLevel
	}

	if cl, err := clientPkg.NewClient(vp.GetString("host")); err != nil {
		Fatalf("Error while creating client: %s\n", err)
	} else {
		client = cl
	}
}

const completionExample = `
# Installing bash completion
## Load the cilium completion code for bash into the current shell
	source <(cilium-dbg completion bash)
## Write bash completion code to a file and source if from .bash_profile
	cilium-dbg completion bash > ~/.cilium/completion.bash.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.bash.inc'
	  " >> $HOME/.bash_profile
	source $HOME/.bash_profile


# Installing zsh completion
## Load the cilium completion code for zsh into the current shell
	source <(cilium-dbg completion zsh)
## Write zsh completion code to a file and source if from .zshrc
	cilium-dbg completion zsh > ~/.cilium/completion.zsh.inc
	printf "
	  # Cilium shell completion
	  source '$HOME/.cilium/completion.zsh.inc'
	  " >> $HOME/.zshrc
	source $HOME/.zshrc

# Installing fish completion
## Write fish completion code to fish specific location
	cilium-dbg completion fish > ~/.config/fish/completions/cilium.fish
`

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
		return cmd.Root().GenBashCompletion(out)
	} else if args[0] == "zsh" {
		return cmd.Root().GenZshCompletion(out)
	} else if args[0] == "fish" {
		return cmd.Root().GenFishCompletion(out, true)
	}
	return fmt.Errorf("unsupported shell: %s", args[0])
}
