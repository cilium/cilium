// Copyright 2020 Authors of Cilium
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

	"github.com/spf13/cobra"
)

const completionExample = `
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
        cilium completion bash > ~/.config/cilium/completion.bash.inc
        printf "
          # Cilium shell completion
          source '$HOME/.config/cilium/completion.bash.inc'
          " >> $HOME/.bash_profile
        source $HOME/.bash_profile

# Installing zsh completion on Linux/macOS
## Load the Cilium completion code for zsh into the current shell
        source <(cilium completion zsh)
## Write zsh completion code to a file and source if from .zshrc
        cilium completion zsh > ~/.config/cilium/completion.zsh.inc
        printf "
          # Cilium shell completion
          source '$HOME/.config/cilium/completion.zsh.inc'
          " >> $HOME/.zshrc
        source $HOME/.zshrc

# Installing fish completion on Linux/macOS
## Load the cilium completion code for fish into the current shell
        cilium completion fish | source
## Write fish completion code to a file
        cilium completion fish > ~/.config/fish/completions/cilium.fish
`

func newCmdCompletion() *cobra.Command {
	return &cobra.Command{
		Use:     "completion [shell]",
		Short:   "Output Shell completion code",
		Long:    ``,
		Example: completionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("too many arguments; expected only the shell type")
			}

			out := cmd.OutOrStdout()
			if len(args) == 0 {
				return cmd.Root().GenBashCompletion(out)
			}

			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(out)
			case "zsh":
				return cmd.Root().GenZshCompletion(out)
			case "fish":
				return cmd.Root().GenFishCompletion(out, true)
			case "powershell", "ps1":
				return cmd.Root().GenPowerShellCompletion(out)
			}
			return fmt.Errorf("unsupported shell type: %s", args[0])

		},
		ValidArgs: []string{"bash", "fish", "powershell", "ps1", "zsh"},
	}
}
