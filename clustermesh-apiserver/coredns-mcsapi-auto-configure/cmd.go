// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package corednsMCSAPIAutoConfigure

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyappsv1 "k8s.io/client-go/applyconfigurations/apps/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "coredns-mcsapi-auto-configure",
		Short: "Automatically configure CoreDNS with recommended MCS-API settings",
		Run: func(cmd *cobra.Command, args []string) {
			// slogloggercheck: it has been initialized in the PreRun function.
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, err.Error())
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			option.Config.SetupLogging(h.Viper(), "coredns-mcsapi-auto-configure")

			// slogloggercheck: the logger has been initialized in the SetupLogging call above
			log := logging.DefaultSlogLogger.With(logfields.LogSubsys, "coredns-mcsapi-auto-configure")

			option.Config.Populate(log, h.Viper())
			option.LogRegisteredSlogOptions(h.Viper(), log)
			log.Info("Cilium MCS-API CoreDNS auto configuration", logfields.Version, version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())

	return rootCmd
}

func configureCoreDNS(jg job.Group, logger *slog.Logger, shutdowner hive.Shutdowner, client client.Clientset, config coreDNSConfig) {
	jg.Add(job.OneShot("clustermesh-nodemanager-notifier", func(ctx context.Context, _ cell.Health) (err error) {
		logger.Info("Starting MCS-API CoreDNS auto configuration")
		defer func() {
			shutdowner.Shutdown(hive.ShutdownWithError(err))
		}()

		if !client.IsEnabled() {
			err = fmt.Errorf("Kubernetes client is not enabled, cannot configure CoreDNS")
			fmt.Println(err.Error())
			return
		}

		var coreDNSConfigmap *corev1.ConfigMap
		coreDNSConfigmap, err = client.CoreV1().ConfigMaps(config.CoreDNSNamespace).Get(ctx, config.CoreDNSConfigMapName, metav1.GetOptions{})
		if err != nil {
			logger.Error("Failed to get CoreDNS ConfigMap", logfields.Error, err)
			return
		}

		var corefile string
		var found bool
		if corefile, found = coreDNSConfigmap.Data["Corefile"]; !found {
			err = fmt.Errorf("Corefile not found in ConfigMap %s/%s", config.CoreDNSNamespace, config.CoreDNSConfigMapName)
			logger.Error(err.Error())
			return
		}

		if corefile, err = updateCorefile(config.CoreDNSClusterDomain, config.CoreDNSClustersetDomain, corefile); err != nil {
			logger.Error("Failed to update CoreDNS Corefile", logfields.Error, err)
			return
		}
		if corefile == "" {
			logger.Info("CoreDNS might already have MCS-API configuration, skipping configuration")
			return
		}
		coreDNSConfigmap.Data["Corefile"] = corefile

		if _, err = client.CoreV1().ConfigMaps(config.CoreDNSNamespace).Update(ctx, coreDNSConfigmap, metav1.UpdateOptions{}); err != nil {
			logger.Error("Failed to update CoreDNS ConfigMap", logfields.Error, err)
			return
		}

		logger.Info("CoreDNS ConfigMap was updated successfully")

		err = restartCoreDNS(ctx, client, config)
		if err != nil {
			logger.Error("Failed to restart CoreDNS Deployment", logfields.Error, err)
		} else {
			logger.Info("CoreDNS is rolling out with the new configuration")
		}
		return
	}))
}

func updateCorefile(clusterDomain, clustersetDomain string, corefile string) (string, error) {
	if strings.Contains(corefile, clustersetDomain) || strings.Contains(corefile, "multicluster") {
		return "", nil // This is not an error as this command might have already been executed
	}

	clusterDomainEscaped := strings.ReplaceAll(clusterDomain, ".", "\\.")
	kubernetesMatchRegex, err := regexp.Compile(fmt.Sprintf(`(?m)^\s*kubernetes.*%s.*\{`, clusterDomainEscaped))
	if err != nil {
		return "", fmt.Errorf("Failed to compile regex for kubernetes plugin matching: %w", err)
	}
	if !kubernetesMatchRegex.MatchString(corefile) {
		return "", fmt.Errorf("CoreDNS not configured with kubernetes plugin and the domain '%s'", clusterDomain)
	}

	corefile = strings.ReplaceAll(
		corefile,
		clusterDomain,
		clusterDomain+" "+clustersetDomain,
	)
	kubernetesReplaceRegex := regexp.MustCompile(`(?m)^(\s*)kubernetes(.*)\{`)
	corefile = kubernetesReplaceRegex.ReplaceAllString(
		corefile,
		fmt.Sprintf("${1}kubernetes${2}{\n${1}   multicluster %s", clustersetDomain),
	)
	return corefile, nil
}

func restartCoreDNS(ctx context.Context, client client.Clientset, config coreDNSConfig) error {
	existingDeployment, err := client.AppsV1().Deployments(config.CoreDNSNamespace).Get(ctx, config.CoreDNSDeploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf(
			"Failed to get CoreDNS Deployment %s/%s: %w",
			config.CoreDNSNamespace, config.CoreDNSDeploymentName, err,
		)
	}

	if existingDeployment.Spec.Paused {
		return fmt.Errorf(
			"Deployment %s/%s is paused",
			config.CoreDNSNamespace, config.CoreDNSDeploymentName,
		)
	}

	_, err = client.AppsV1().Deployments(config.CoreDNSNamespace).Apply(
		ctx,
		applyappsv1.Deployment(config.CoreDNSDeploymentName, config.CoreDNSNamespace).
			WithAnnotations(map[string]string{
				"kubectl.kubernetes.io/restartedAt": time.Now().Format(time.RFC3339),
			}),
		metav1.ApplyOptions{FieldManager: "mcsapi-coredns-autocfg", Force: true},
	)
	if err != nil {
		return fmt.Errorf(
			"Failed to apply Deployment %s/%s: %w",
			config.CoreDNSNamespace, config.CoreDNSDeploymentName, err,
		)
	}

	return nil
}
