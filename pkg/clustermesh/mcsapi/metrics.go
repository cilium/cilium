// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

const subsystem = "mcsapi"

func registerMCSAPICollector(registry *metrics.Registry, logger *slog.Logger, client client.Client) {
	registry.MustRegister(&mcsAPICollector{
		logger: logger,
		client: client,

		serviceExportInfo: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, subsystem, "serviceexport_info"),
			"Information about ServiceExport in the local cluster",
			[]string{"serviceexport", "namespace"}, nil),
		serviceExportStatusCondition: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, subsystem, "serviceexport_status_condition"),
			"Status Condition of ServiceExport in the local cluster",
			[]string{"serviceexport", "namespace", "condition", "status", "reason"}, nil),
		serviceImportInfo: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, subsystem, "serviceimport_info"),
			"Information about ServiceImport in the local cluster",
			[]string{"serviceimport", "namespace"}, nil),
		serviceImportStatusCondition: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, subsystem, "serviceimport_status_condition"),
			"Status Condition of ServiceImport in the local cluster",
			[]string{"serviceimport", "namespace", "condition", "status", "reason"}, nil),
		serviceImportStatusClusters: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.CiliumOperatorNamespace, subsystem, "serviceimport_status_clusters"),
			"The number of clusters currently backing a ServiceImport",
			[]string{"serviceimport", "namespace"}, nil),
	})
}

type mcsAPICollector struct {
	logger *slog.Logger
	client client.Client

	serviceExportInfo            *prometheus.Desc
	serviceExportStatusCondition *prometheus.Desc
	serviceImportInfo            *prometheus.Desc
	serviceImportStatusCondition *prometheus.Desc
	serviceImportStatusClusters  *prometheus.Desc
}

func (c *mcsAPICollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceExportInfo
	ch <- c.serviceExportStatusCondition
	ch <- c.serviceImportInfo
	ch <- c.serviceImportStatusCondition
	ch <- c.serviceImportStatusClusters
}

func (c *mcsAPICollector) Collect(ch chan<- prometheus.Metric) {
	svcExportList := mcsapiv1alpha1.ServiceExportList{}
	err := c.client.List(context.Background(), &svcExportList)
	if err != nil {
		c.logger.Error("failed to list ServiceExport during metrics collection", logfields.Error, err)
		return
	}
	for _, svcExport := range svcExportList.Items {
		metric, err := prometheus.NewConstMetric(
			c.serviceExportInfo,
			prometheus.GaugeValue,
			1,
			svcExport.Name, svcExport.Namespace,
		)
		if err != nil {
			c.logger.Error("Failed to generate ServiceExport metrics", logfields.Error, err)
			return
		}
		ch <- metric
		for _, condition := range svcExport.Status.Conditions {
			metric, err := prometheus.NewConstMetric(
				c.serviceExportStatusCondition,
				prometheus.GaugeValue,
				1,
				svcExport.Name, svcExport.Namespace,
				string(condition.Type), string(condition.Status), condition.Reason,
			)
			if err != nil {
				c.logger.Error("Failed to generate ServiceExport metrics", logfields.Error, err)
				return
			}
			ch <- metric
		}
	}

	svcImportList := mcsapiv1alpha1.ServiceImportList{}
	err = c.client.List(context.Background(), &svcImportList)
	if err != nil {
		c.logger.Error("failed to list ServiceImport during metrics collection", logfields.Error, err)
		return
	}
	for _, svcImport := range svcImportList.Items {
		metric, err := prometheus.NewConstMetric(
			c.serviceImportInfo,
			prometheus.GaugeValue,
			1,
			svcImport.Name, svcImport.Namespace,
		)
		if err != nil {
			c.logger.Error("Failed to generate ServiceImport metrics", logfields.Error, err)
			return
		}
		ch <- metric
		metric, err = prometheus.NewConstMetric(
			c.serviceImportStatusClusters,
			prometheus.GaugeValue,
			float64(len(svcImport.Status.Clusters)),
			svcImport.Name, svcImport.Namespace,
		)
		if err != nil {
			c.logger.Error("Failed to generate ServiceImport metrics", logfields.Error, err)
			return
		}
		ch <- metric
		for _, condition := range svcImport.Status.Conditions {
			metric, err := prometheus.NewConstMetric(
				c.serviceImportStatusCondition,
				prometheus.GaugeValue,
				1,
				svcImport.Name, svcImport.Namespace,
				string(condition.Type), string(condition.Status), condition.Reason,
			)
			if err != nil {
				c.logger.Error("Failed to generate ServiceImport metrics", logfields.Error, err)
				return
			}
			ch <- metric
		}
	}
}
