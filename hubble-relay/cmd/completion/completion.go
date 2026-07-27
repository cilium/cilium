// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package completion

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// New creates a new shell completion command.
func New() *cobra.Command {
	return &cobra.Command{
		Use:     "completion [shell]",
		Short:   "Output shell completion code",
		Long:    "Output shell completion code for bash and zsh",
		Example: completionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompletion(cmd.OutOrStdout(), cmd, args)
		},
		ValidArgs: []string{"bash", "zsh"},
	}
}

func runCompletion(out io.Writer, cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("too many arguments; expected only the shell type: %s", args)
	}

	if len(args) == 0 || args[0] == "bash" {
		return cmd.Root().GenBashCompletion(out)
	}
	if args[0] == "zsh" {
		return cmd.Root().GenZshCompletion(out)
	}
	return fmt.Errorf("unsupported shell: %s", args[0])
}

const completionExample = `
# Installing bash completion on macOS using homebrew
## If running Bash 3.2 included with macOS
	brew install bash-completion
## or, if running Bash 4.1+
	brew install bash-completion@2
## afterwards you only need to run
	hubble-relay completion bash > $(brew --prefix)/etc/bash_completion.d/hubble-relay


# Installing bash completion on Linux
## Load the hubble-relay completion code for bash into the current shell
	source <(hubble-relay completion bash)
## Write bash completion code to a file and source if from .bash_profile
	hubble-relay completion bash > ~/.hubble-relay/completion.bash.inc
	printf "
	  # hubble-relay shell completion
	  source '$HOME/.hubble-relay/completion.bash.inc'
	  " >> $HOME/.bash_profile
	source $HOME/.bash_profile

# Installing zsh completion on Linux/macOS
## Load the hubble-relay completion code for zsh into the current shell
        source <(hubble-relay completion zsh)
## Write zsh completion code to a file and source if from .zshrc
        hubble-relay completion zsh > ~/.hubble-relay/completion.zsh.inc
        printf "
          # hubble-relay shell completion
          source '$HOME/.hubble-relay/completion.zsh.inc'
          " >> $HOME/.zshrc
        source $HOME/.zshrc`
