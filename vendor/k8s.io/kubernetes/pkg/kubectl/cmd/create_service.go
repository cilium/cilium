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

package cmd

import (
	"io"

	"github.com/spf13/cobra"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/kubectl"
	"k8s.io/kubernetes/pkg/kubectl/cmd/templates"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"
)

// NewCmdCreateService is a macro command to create a new service
func NewCmdCreateService(f cmdutil.Factory, cmdOut, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "service",
		Aliases: []string{"svc"},
		Short:   i18n.T("Create a service using specified subcommand."),
		Long:    "Create a service using specified subcommand.",
		Run:     cmdutil.DefaultSubCommandRun(errOut),
	}
	cmd.AddCommand(NewCmdCreateServiceClusterIP(f, cmdOut))
	cmd.AddCommand(NewCmdCreateServiceNodePort(f, cmdOut))
	cmd.AddCommand(NewCmdCreateServiceLoadBalancer(f, cmdOut))
	cmd.AddCommand(NewCmdCreateServiceExternalName(f, cmdOut))

	return cmd
}

var (
	serviceClusterIPLong = templates.LongDesc(i18n.T(`
    Create a clusterIP service with the specified name.`))

	serviceClusterIPExample = templates.Examples(i18n.T(`
    # Create a new clusterIP service named my-cs
    kubectl create service clusterip my-cs --tcp=5678:8080

    # Create a new clusterIP service named my-cs (in headless mode)
    kubectl create service clusterip my-cs --clusterip="None"`))
)

func addPortFlags(cmd *cobra.Command) {
	cmd.Flags().StringSlice("tcp", []string{}, "Port pairs can be specified as '<port>:<targetPort>'.")
}

// NewCmdCreateServiceClusterIP is a command to create a clusterIP service
func NewCmdCreateServiceClusterIP(f cmdutil.Factory, cmdOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "clusterip NAME [--tcp=<port>:<targetPort>] [--dry-run]",
		Short:   i18n.T("Create a clusterIP service."),
		Long:    serviceClusterIPLong,
		Example: serviceClusterIPExample,
		Run: func(cmd *cobra.Command, args []string) {
			err := CreateServiceClusterIP(f, cmdOut, cmd, args)
			cmdutil.CheckErr(err)
		},
	}
	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddValidateFlags(cmd)
	cmdutil.AddPrinterFlags(cmd)
	cmdutil.AddGeneratorFlags(cmd, cmdutil.ServiceClusterIPGeneratorV1Name)
	addPortFlags(cmd)
	cmd.Flags().String("clusterip", "", i18n.T("Assign your own ClusterIP or set to 'None' for a 'headless' service (no loadbalancing)."))
	return cmd
}

func errUnsupportedGenerator(cmd *cobra.Command, generatorName string) error {
	return cmdutil.UsageErrorf(cmd, "Generator %s not supported. ", generatorName)
}

// CreateServiceClusterIP implements the behavior to run the create service clusterIP command
func CreateServiceClusterIP(f cmdutil.Factory, cmdOut io.Writer, cmd *cobra.Command, args []string) error {
	name, err := NameFromCommandArgs(cmd, args)
	if err != nil {
		return err
	}
	var generator kubectl.StructuredGenerator
	switch generatorName := cmdutil.GetFlagString(cmd, "generator"); generatorName {
	case cmdutil.ServiceClusterIPGeneratorV1Name:
		generator = &kubectl.ServiceCommonGeneratorV1{
			Name:      name,
			TCP:       cmdutil.GetFlagStringSlice(cmd, "tcp"),
			Type:      api.ServiceTypeClusterIP,
			ClusterIP: cmdutil.GetFlagString(cmd, "clusterip"),
		}
	default:
		return errUnsupportedGenerator(cmd, generatorName)
	}
	return RunCreateSubcommand(f, cmd, cmdOut, &CreateSubcommandOptions{
		Name:                name,
		StructuredGenerator: generator,
		DryRun:              cmdutil.GetDryRunFlag(cmd),
		OutputFormat:        cmdutil.GetFlagString(cmd, "output"),
	})
}

var (
	serviceNodePortLong = templates.LongDesc(i18n.T(`
    Create a nodeport service with the specified name.`))

	serviceNodePortExample = templates.Examples(i18n.T(`
    # Create a new nodeport service named my-ns
    kubectl create service nodeport my-ns --tcp=5678:8080`))
)

// NewCmdCreateServiceNodePort is a macro command for creating a NodePort service
func NewCmdCreateServiceNodePort(f cmdutil.Factory, cmdOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "nodeport NAME [--tcp=port:targetPort] [--dry-run]",
		Short:   i18n.T("Create a NodePort service."),
		Long:    serviceNodePortLong,
		Example: serviceNodePortExample,
		Run: func(cmd *cobra.Command, args []string) {
			err := CreateServiceNodePort(f, cmdOut, cmd, args)
			cmdutil.CheckErr(err)
		},
	}
	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddValidateFlags(cmd)
	cmdutil.AddPrinterFlags(cmd)
	cmdutil.AddGeneratorFlags(cmd, cmdutil.ServiceNodePortGeneratorV1Name)
	cmd.Flags().Int("node-port", 0, "Port used to expose the service on each node in a cluster.")
	addPortFlags(cmd)
	return cmd
}

// CreateServiceNodePort is the implementation of the create service nodeport command
func CreateServiceNodePort(f cmdutil.Factory, cmdOut io.Writer, cmd *cobra.Command, args []string) error {
	name, err := NameFromCommandArgs(cmd, args)
	if err != nil {
		return err
	}
	var generator kubectl.StructuredGenerator
	switch generatorName := cmdutil.GetFlagString(cmd, "generator"); generatorName {
	case cmdutil.ServiceNodePortGeneratorV1Name:
		generator = &kubectl.ServiceCommonGeneratorV1{
			Name:      name,
			TCP:       cmdutil.GetFlagStringSlice(cmd, "tcp"),
			Type:      api.ServiceTypeNodePort,
			ClusterIP: "",
			NodePort:  cmdutil.GetFlagInt(cmd, "node-port"),
		}
	default:
		return errUnsupportedGenerator(cmd, generatorName)
	}
	return RunCreateSubcommand(f, cmd, cmdOut, &CreateSubcommandOptions{
		Name:                name,
		StructuredGenerator: generator,
		DryRun:              cmdutil.GetDryRunFlag(cmd),
		OutputFormat:        cmdutil.GetFlagString(cmd, "output"),
	})
}

var (
	serviceLoadBalancerLong = templates.LongDesc(i18n.T(`
    Create a LoadBalancer service with the specified name.`))

	serviceLoadBalancerExample = templates.Examples(i18n.T(`
    # Create a new LoadBalancer service named my-lbs
    kubectl create service loadbalancer my-lbs --tcp=5678:8080`))
)

// NewCmdCreateServiceLoadBalancer is a macro command for creating a LoadBalancer service
func NewCmdCreateServiceLoadBalancer(f cmdutil.Factory, cmdOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "loadbalancer NAME [--tcp=port:targetPort] [--dry-run]",
		Short:   i18n.T("Create a LoadBalancer service."),
		Long:    serviceLoadBalancerLong,
		Example: serviceLoadBalancerExample,
		Run: func(cmd *cobra.Command, args []string) {
			err := CreateServiceLoadBalancer(f, cmdOut, cmd, args)
			cmdutil.CheckErr(err)
		},
	}
	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddValidateFlags(cmd)
	cmdutil.AddPrinterFlags(cmd)
	cmdutil.AddGeneratorFlags(cmd, cmdutil.ServiceLoadBalancerGeneratorV1Name)
	addPortFlags(cmd)
	return cmd
}

// CreateServiceLoadBalancer is the implementation of the service loadbalancer command
func CreateServiceLoadBalancer(f cmdutil.Factory, cmdOut io.Writer, cmd *cobra.Command, args []string) error {
	name, err := NameFromCommandArgs(cmd, args)
	if err != nil {
		return err
	}
	var generator kubectl.StructuredGenerator
	switch generatorName := cmdutil.GetFlagString(cmd, "generator"); generatorName {
	case cmdutil.ServiceLoadBalancerGeneratorV1Name:
		generator = &kubectl.ServiceCommonGeneratorV1{
			Name:      name,
			TCP:       cmdutil.GetFlagStringSlice(cmd, "tcp"),
			Type:      api.ServiceTypeLoadBalancer,
			ClusterIP: "",
		}
	default:
		return errUnsupportedGenerator(cmd, generatorName)
	}
	return RunCreateSubcommand(f, cmd, cmdOut, &CreateSubcommandOptions{
		Name:                name,
		StructuredGenerator: generator,
		DryRun:              cmdutil.GetFlagBool(cmd, "dry-run"),
		OutputFormat:        cmdutil.GetFlagString(cmd, "output"),
	})
}

var (
	serviceExternalNameLong = templates.LongDesc(i18n.T(`
	Create an ExternalName service with the specified name.

	ExternalName service references to an external DNS address instead of
	only pods, which will allow application authors to reference services
	that exist off platform, on other clusters, or locally.`))

	serviceExternalNameExample = templates.Examples(i18n.T(`
	# Create a new ExternalName service named my-ns 
	kubectl create service externalname my-ns --external-name bar.com`))
)

// NewCmdCreateServiceExternalName is a macro command for creating a ExternalName service
func NewCmdCreateServiceExternalName(f cmdutil.Factory, cmdOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "externalname NAME --external-name external.name [--dry-run]",
		Short:   i18n.T("Create an ExternalName service."),
		Long:    serviceExternalNameLong,
		Example: serviceExternalNameExample,
		Run: func(cmd *cobra.Command, args []string) {
			err := CreateExternalNameService(f, cmdOut, cmd, args)
			cmdutil.CheckErr(err)
		},
	}
	cmdutil.AddApplyAnnotationFlags(cmd)
	cmdutil.AddValidateFlags(cmd)
	cmdutil.AddPrinterFlags(cmd)
	cmdutil.AddGeneratorFlags(cmd, cmdutil.ServiceExternalNameGeneratorV1Name)
	addPortFlags(cmd)
	cmd.Flags().String("external-name", "", i18n.T("External name of service"))
	cmd.MarkFlagRequired("external-name")
	return cmd
}

// CreateExternalNameService is the implementation of the service externalname command
func CreateExternalNameService(f cmdutil.Factory, cmdOut io.Writer, cmd *cobra.Command, args []string) error {
	name, err := NameFromCommandArgs(cmd, args)
	if err != nil {
		return err
	}
	var generator kubectl.StructuredGenerator
	switch generatorName := cmdutil.GetFlagString(cmd, "generator"); generatorName {
	case cmdutil.ServiceExternalNameGeneratorV1Name:
		generator = &kubectl.ServiceCommonGeneratorV1{
			Name:         name,
			Type:         api.ServiceTypeExternalName,
			ExternalName: cmdutil.GetFlagString(cmd, "external-name"),
			ClusterIP:    "",
		}
	default:
		return errUnsupportedGenerator(cmd, generatorName)
	}
	return RunCreateSubcommand(f, cmd, cmdOut, &CreateSubcommandOptions{
		Name:                name,
		StructuredGenerator: generator,
		DryRun:              cmdutil.GetDryRunFlag(cmd),
		OutputFormat:        cmdutil.GetFlagString(cmd, "output"),
	})
}
