// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

func registerMCSAPICollector(logger *slog.Logger, client k8sClient.Clientset) {
	operatorMetrics.Registry.MustRegister(&mcsAPICollector{
		logger: logger,
		client: client,

		serviceExportCreated: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, "", "service_export_created"),
			"Number of ServiceExport created in the local cluster",
			[]string{"serviceexport", "namespace"}, nil),
		serviceExportStatusCondition: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, "", "service_export_status_condition"),
			"Status Condition of ServiceExport in the local cluster",
			[]string{"serviceexport", "namespace", "condition", "status"}, nil),
		serviceImportCreated: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, "", "service_import_created"),
			"Number of ServiceImport created in the local cluster",
			[]string{"serviceimport", "namespace"}, nil),
	})
}

type mcsAPICollector struct {
	logger *slog.Logger
	client k8sClient.Clientset

	serviceExportCreated         *prometheus.Desc
	serviceExportStatusCondition *prometheus.Desc
	serviceImportCreated         *prometheus.Desc
}

func (c *mcsAPICollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceExportCreated
	ch <- c.serviceExportStatusCondition
	ch <- c.serviceImportCreated
}

func (c *mcsAPICollector) Collect(ch chan<- prometheus.Metric) {
	svcExportList, err := c.client.MulticlusterV1alpha1().ServiceExports(corev1.NamespaceAll).List(context.Background(), metav1.ListOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		c.logger.Error("failed to list ServiceExport during metrics collection", logfields.Error, err)
		return
	}
	for _, svcExport := range svcExportList.Items {
		ch <- prometheus.MustNewConstMetric(
			c.serviceExportCreated,
			prometheus.GaugeValue,
			1,
			svcExport.Name, svcExport.Namespace,
		)
		for _, condition := range svcExport.Status.Conditions {
			ch <- prometheus.MustNewConstMetric(
				c.serviceExportStatusCondition,
				prometheus.GaugeValue,
				1,
				svcExport.Name, svcExport.Namespace,
				string(condition.Type), string(condition.Status),
			)
		}
	}

	svcImportList, err := c.client.MulticlusterV1alpha1().ServiceImports(corev1.NamespaceAll).List(context.Background(), metav1.ListOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		c.logger.Error("failed to list ServiceImport during metrics collection", logfields.Error, err)
		return
	}
	for _, svcImport := range svcImportList.Items {
		ch <- prometheus.MustNewConstMetric(
			c.serviceImportCreated,
			prometheus.GaugeValue,
			1,
			svcImport.Name, svcImport.Namespace,
		)
	}
}
