/*
Copyright 2016 The Kubernetes Authors.

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

package kubefed

import (
	"io"

	"k8s.io/apiserver/pkg/util/flag"
	"k8s.io/client-go/tools/clientcmd"
	kubefedinit "k8s.io/kubernetes/federation/pkg/kubefed/init"
	"k8s.io/kubernetes/federation/pkg/kubefed/util"
	kubectl "k8s.io/kubernetes/pkg/kubectl/cmd"
	"k8s.io/kubernetes/pkg/kubectl/cmd/templates"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"

	"github.com/spf13/cobra"
)

var (
	kubefedVersionExample = templates.Examples(i18n.T(`
		# Print the client and server versions for the current context
		kubefed version`))
	kubefedOptionsExample = templates.Examples(i18n.T(`
		# Print flags inherited by all commands
		kubefed options`))
)

// NewKubeFedCommand creates the `kubefed` command and its nested children.
func NewKubeFedCommand(f cmdutil.Factory, in io.Reader, out, err io.Writer, defaultServerImage, defaultEtcdImage string) *cobra.Command {
	// Parent command to which all subcommands are added.
	cmds := &cobra.Command{
		Use:   "kubefed",
		Short: "kubefed controls a Kubernetes Cluster Federation",
		Long: templates.LongDesc(`
      kubefed controls a Kubernetes Cluster Federation.

      Find more information at https://github.com/kubernetes/kubernetes.`),
		Run: runHelp,
	}

	f.BindFlags(cmds.PersistentFlags())
	f.BindExternalFlags(cmds.PersistentFlags())

	// From this point and forward we get warnings on flags that contain "_" separators
	cmds.SetGlobalNormalizationFunc(flag.WarnWordSepNormalizeFunc)

	groups := templates.CommandGroups{
		{
			Message: "Basic Commands:",
			Commands: []*cobra.Command{
				kubefedinit.NewCmdInit(out, util.NewAdminConfig(clientcmd.NewDefaultPathOptions()), defaultServerImage, defaultEtcdImage),
				NewCmdJoin(f, out, util.NewAdminConfig(clientcmd.NewDefaultPathOptions())),
				NewCmdUnjoin(f, out, err, util.NewAdminConfig(clientcmd.NewDefaultPathOptions())),
			},
		},
	}
	groups.Add(cmds)

	filters := []string{
		"options",
	}
	templates.ActsAsRootCommand(cmds, filters, groups...)

	cmdVersion := kubectl.NewCmdVersion(f, out)
	cmdVersion.Example = kubefedVersionExample
	cmds.AddCommand(cmdVersion)
	cmdOptions := kubectl.NewCmdOptions(out)
	cmdOptions.Example = kubefedOptionsExample
	cmds.AddCommand(cmdOptions)

	return cmds
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
