/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/renstrom/dedent"
	"github.com/spf13/cobra"

	kubeadmutil "k8s.io/kubernetes/cmd/kubeadm/app/util"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"
)

const defaultBoilerPlate = `
# Copyright 2017 The Kubernetes Authors.
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
	completion_long = dedent.Dedent(`
		Output shell completion code for the specified shell (bash or zsh).
		The shell code must be evalutated to provide interactive
		completion of kubeadm commands.  This can be done by sourcing it from
		the .bash_profile.

		Note: this requires the bash-completion framework, which is not installed
		by default on Mac.  This can be installed by using homebrew:

		    $ brew install bash-completion

		Once installed, bash_completion must be evaluated.  This can be done by adding the
		following line to the .bash_profile

		    $ source $(brew --prefix)/etc/bash_completion

		Note for zsh users: [1] zsh completions are only supported in versions of zsh >= 5.2`)

	completion_example = dedent.Dedent(`
		# Install bash completion on a Mac using homebrew
		brew install bash-completion
		printf "\n# Bash completion support\nsource $(brew --prefix)/etc/bash_completion\n" >> $HOME/.bash_profile
		source $HOME/.bash_profile

		# Load the kubeadm completion code for bash into the current shell
		source <(kubeadm completion bash)

		# Write bash completion code to a file and source if from .bash_profile
		kubeadm completion bash > ~/.kube/kubeadm_completion.bash.inc
		printf "\n# Kubeadm shell completion\nsource '$HOME/.kube/kubeadm_completion.bash.inc'\n" >> $HOME/.bash_profile
		source $HOME/.bash_profile

		# Load the kubeadm completion code for zsh[1] into the current shell
		source <(kubeadm completion zsh)`)
)

var (
	completion_shells = map[string]func(out io.Writer, cmd *cobra.Command) error{
		"bash": runCompletionBash,
		"zsh":  runCompletionZsh,
	}
)

func NewCmdCompletion(out io.Writer, boilerPlate string) *cobra.Command {
	shells := []string{}
	for s := range completion_shells {
		shells = append(shells, s)
	}

	cmd := &cobra.Command{
		Use:     "completion SHELL",
		Short:   i18n.T("Output shell completion code for the specified shell (bash or zsh)"),
		Long:    completion_long,
		Example: completion_example,
		Run: func(cmd *cobra.Command, args []string) {
			err := RunCompletion(out, boilerPlate, cmd, args)
			kubeadmutil.CheckErr(err)
		},
		ValidArgs: shells,
	}

	return cmd
}

func RunCompletion(out io.Writer, boilerPlate string, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("shell not specified.")
	}
	if len(args) > 1 {
		return fmt.Errorf("too many arguments. expected only the shell type.")
	}
	run, found := completion_shells[args[0]]
	if !found {
		return fmt.Errorf("unsupported shell type %q.", args[0])
	}

	if len(boilerPlate) == 0 {
		boilerPlate = defaultBoilerPlate
	}
	if _, err := out.Write([]byte(boilerPlate)); err != nil {
		return err
	}
	return run(out, cmd.Parent())
}

func runCompletionBash(out io.Writer, kubeadm *cobra.Command) error {
	return kubeadm.GenBashCompletion(out)
}

func runCompletionZsh(out io.Writer, kubeadm *cobra.Command) error {
	zsh_initialization := `
__kubeadm_bash_source() {
	alias shopt=':'
	alias _expand=_bash_expand
	alias _complete=_bash_comp
	emulate -L sh
	setopt kshglob noshglob braceexpand

	source "$@"
}

__kubeadm_type() {
	# -t is not supported by zsh
	if [ "$1" == "-t" ]; then
		shift

		# fake Bash 4 to disable "complete -o nospace". Instead
		# "compopt +-o nospace" is used in the code to toggle trailing
		# spaces. We don't support that, but leave trailing spaces on
		# all the time
		if [ "$1" = "__kubeadm_compopt" ]; then
			echo builtin
			return 0
		fi
	fi
	type "$@"
}

__kubeadm_compgen() {
	local completions w
	completions=( $(compgen "$@") ) || return $?

	# filter by given word as prefix
	while [[ "$1" = -* && "$1" != -- ]]; do
		shift
		shift
	done
	if [[ "$1" == -- ]]; then
		shift
	fi
	for w in "${completions[@]}"; do
		if [[ "${w}" = "$1"* ]]; then
			echo "${w}"
		fi
	done
}

__kubeadm_compopt() {
	true # don't do anything. Not supported by bashcompinit in zsh
}

__kubeadm_ltrim_colon_completions()
{
	if [[ "$1" == *:* && "$COMP_WORDBREAKS" == *:* ]]; then
		# Remove colon-word prefix from COMPREPLY items
		local colon_word=${1%${1##*:}}
		local i=${#COMPREPLY[*]}
		while [[ $((--i)) -ge 0 ]]; do
			COMPREPLY[$i]=${COMPREPLY[$i]#"$colon_word"}
		done
	fi
}

__kubeadm_get_comp_words_by_ref() {
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[${COMP_CWORD}-1]}"
	words=("${COMP_WORDS[@]}")
	cword=("${COMP_CWORD[@]}")
}

__kubeadm_filedir() {
	local RET OLD_IFS w qw

	__debug "_filedir $@ cur=$cur"
	if [[ "$1" = \~* ]]; then
		# somehow does not work. Maybe, zsh does not call this at all
		eval echo "$1"
		return 0
	fi

	OLD_IFS="$IFS"
	IFS=$'\n'
	if [ "$1" = "-d" ]; then
		shift
		RET=( $(compgen -d) )
	else
		RET=( $(compgen -f) )
	fi
	IFS="$OLD_IFS"

	IFS="," __debug "RET=${RET[@]} len=${#RET[@]}"

	for w in ${RET[@]}; do
		if [[ ! "${w}" = "${cur}"* ]]; then
			continue
		fi
		if eval "[[ \"\${w}\" = *.$1 || -d \"\${w}\" ]]"; then
			qw="$(__kubeadm_quote "${w}")"
			if [ -d "${w}" ]; then
				COMPREPLY+=("${qw}/")
			else
				COMPREPLY+=("${qw}")
			fi
		fi
	done
}

__kubeadm_quote() {
    if [[ $1 == \'* || $1 == \"* ]]; then
        # Leave out first character
        printf %q "${1:1}"
    else
    	printf %q "$1"
    fi
}

autoload -U +X bashcompinit && bashcompinit

# use word boundary patterns for BSD or GNU sed
LWORD='[[:<:]]'
RWORD='[[:>:]]'
if sed --help 2>&1 | grep -q GNU; then
	LWORD='\<'
	RWORD='\>'
fi

__kubeadm_convert_bash_to_zsh() {
	sed \
	-e 's/declare -F/whence -w/' \
	-e 's/local \([a-zA-Z0-9_]*\)=/local \1; \1=/' \
	-e 's/flags+=("\(--.*\)=")/flags+=("\1"); two_word_flags+=("\1")/' \
	-e 's/must_have_one_flag+=("\(--.*\)=")/must_have_one_flag+=("\1")/' \
	-e "s/${LWORD}_filedir${RWORD}/__kubeadm_filedir/g" \
	-e "s/${LWORD}_get_comp_words_by_ref${RWORD}/__kubeadm_get_comp_words_by_ref/g" \
	-e "s/${LWORD}__ltrim_colon_completions${RWORD}/__kubeadm_ltrim_colon_completions/g" \
	-e "s/${LWORD}compgen${RWORD}/__kubeadm_compgen/g" \
	-e "s/${LWORD}compopt${RWORD}/__kubeadm_compopt/g" \
	-e "s/${LWORD}declare${RWORD}/builtin declare/g" \
	-e "s/\\\$(type${RWORD}/\$(__kubeadm_type/g" \
	<<'BASH_COMPLETION_EOF'
`
	out.Write([]byte(zsh_initialization))

	buf := new(bytes.Buffer)
	kubeadm.GenBashCompletion(buf)
	out.Write(buf.Bytes())

	zsh_tail := `
BASH_COMPLETION_EOF
}

__kubeadm_bash_source <(__kubeadm_convert_bash_to_zsh)
`
	out.Write([]byte(zsh_tail))
	return nil
}
