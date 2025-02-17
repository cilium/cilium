// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	// See https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
	// tags are conditionally set based on description
	metricAzureRateLimitRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "azure_ratelimit_remaining",
		Help: "Rate limit metrics grouped by description, see https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests for more information. Example description: Subscription-Reads",
	}, []string{
		rateLimitRemainingDescriptionTag,
		rateLimitRemainingTenantIDTag,
		rateLimitRemainingSubscriptionIDTag,
		rateLimitRemainingResourceTypeTag,
	})
	rateLimitMetricHeaderPrefix         = "X-Ms-Ratelimit-Remaining-"
	rateLimitRemainingDescriptionTag    = "description"
	rateLimitRemainingTenantIDTag       = "tenant_id"
	rateLimitRemainingSubscriptionIDTag = "subscription_id"
	rateLimitRemainingResourceTypeTag   = "resource_type"

	// See https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
	metricAzureRateLimitRemainingResource = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "azure_ratelimit_remaining_resource",
		Help: "Rate limit resource metrics grouped by policy, see https://docs.microsoft.com/en-us/azure/virtual-machines/troubleshooting/troubleshooting-throttling-errors#call-rate-informational-response-headers for more information. Example description: Microsoft.Compute/HighCostGet3Min",
	}, []string{
		rateLimitRemainingPolicyTag,
		rateLimitRemainingTenantIDTag,
		rateLimitRemainingSubscriptionIDTag,
		rateLimitRemainingResourceTypeTag,
	})
	rateLimitRemainingResourceHeader = "X-Ms-Ratelimit-Remaining-Resource"
	rateLimitRemainingPolicyTag      = "policy"

	// See docs https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling#remaining-requests
	rateLimitDescriptionToRequiredTags = map[string]map[string]struct{}{
		// Subscription scoped reads remaining. This value is returned on read operations.
		"subscription-reads": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},
		// Subscription scoped writes remaining. This value is returned on write operations.
		"subscription-writes": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},
		// Subscription scoped writes remaining. This value is returned on delete operations.
		"subscription-deletes": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},
		// global limits should be 15x the individual limits
		// Subscription scoped reads remaining. This value is returned on read operations.
		"subscription-global-reads": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},
		// Subscription scoped writes remaining. This value is returned on write operations.
		"subscription-global-writes": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},
		// Subscription scoped writes remaining. This value is returned on delete operations.
		"subscription-global-deletes": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
		},

		// Tenant scoped reads remaining
		"tenant-reads": {
			rateLimitRemainingDescriptionTag: {},
			rateLimitRemainingTenantIDTag:    {},
		},
		// Tenant scoped writes remaining
		"tenant-writes": {
			rateLimitRemainingDescriptionTag: {},
			rateLimitRemainingTenantIDTag:    {},
		},
		// Subscription scoped resource type requests remaining.
		//
		// This header value is only returned if a service has overridden the default limit. Resource Manager adds this value instead of the subscription reads or writes.
		"subscription-resource-requests": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
			rateLimitRemainingResourceTypeTag:   {},
		},
		// Subscription scoped resource type collection requests remaining.
		//
		// This header value is only returned if a service has overridden the default limit. This value provides the number of remaining collection requests (list resources).
		"subscription-resource-entities-read": {
			rateLimitRemainingDescriptionTag:    {},
			rateLimitRemainingTenantIDTag:       {},
			rateLimitRemainingSubscriptionIDTag: {},
			rateLimitRemainingResourceTypeTag:   {},
		},
		// Tenant scoped resource type requests remaining.
		//
		// This header is only added for requests at tenant level, and only if a service has overridden the default limit. Resource Manager adds this value instead of the tenant reads or writes.
		"tenant-resource-requests": {
			rateLimitRemainingDescriptionTag:  {},
			rateLimitRemainingTenantIDTag:     {},
			rateLimitRemainingResourceTypeTag: {},
		},
		// Tenant scoped resource type collection requests remaining.
		//
		// This header is only added for requests at tenant level, and only if a service has overridden the default limit.
		"tenant-resource-entities-read": {
			rateLimitRemainingDescriptionTag:  {},
			rateLimitRemainingTenantIDTag:     {},
			rateLimitRemainingResourceTypeTag: {},
		},
	}

	metricAzureRateLimitHeaderParseError = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "azure_rate_limit_header_parse_error_count",
		Help: "Count of the number of errors encountered while to parse rate limit headers.",
	})
)

type MetricsExtractor struct {
	logger         *logrus.Entry
	tenantID       string
	subscriptionID string
	resourceType   string
}

// Ensure that MetricsExtractor implements the policy.Policy interface
var _ policy.Policy = &MetricsExtractor{}

func NewMetricsExtractor(logger *logrus.Entry, subscriptionID string, tenantID string, resourceType string, registry operatorMetrics.RegisterGatherer) *MetricsExtractor {
	registry.MustRegister(
		metricAzureRateLimitRemaining,
		metricAzureRateLimitRemainingResource,
		metricAzureRateLimitHeaderParseError,
	)
	return &MetricsExtractor{
		logger:         logger,
		tenantID:       tenantID,
		subscriptionID: subscriptionID,
		resourceType:   resourceType,
	}
}

func (m *MetricsExtractor) extractMetrics(response *http.Response) error {
	if response == nil || response.Request == nil || response.Request.URL == nil {
		return nil
	}
	logger := m.logger.WithFields(logrus.Fields{"url": response.Request.URL.String(), "status": response.Status, "method": response.Request.Method})
	metricResults, err := m.getRequestLimitMetrics(response)
	if err != nil {
		metricAzureRateLimitHeaderParseError.Inc()
		logger.Error(err, "Failed to get metrics from response")
	}
	for _, metricResult := range metricResults {
		gauge, err := metricAzureRateLimitRemaining.GetMetricWithLabelValues(metricResult.TagValues...)
		if err != nil {
			logger.Error(err, "Failed to get metric with tag values")
		} else {
			gauge.Set(metricResult.Value)
		}
	}
	metricResults, err = m.getRequestLimitResourceMetrics(response)
	if err != nil {
		metricAzureRateLimitHeaderParseError.Inc()
		logger.Error(err, "Failed to get resource metrics from response")
	}
	for _, metricResult := range metricResults {
		gauge, err := metricAzureRateLimitRemainingResource.GetMetricWithLabelValues(metricResult.TagValues...)
		if err != nil {
			logger.Error(err, "Failed to get metric with tag values")
		} else {
			gauge.Set(metricResult.Value)
		}
	}
	return nil
}

type metricResult struct {
	TagValues []string
	Value     float64
}

func (m *MetricsExtractor) getRequestLimitMetrics(response *http.Response) ([]metricResult, error) {
	var ret []metricResult
	var headerKeys []string
	for headerKey := range response.Header {
		headerKeys = append(headerKeys, headerKey)
	}
	sort.Strings(headerKeys)
	for _, headerKey := range headerKeys {
		headerValue := response.Header.Get(headerKey)
		if strings.HasPrefix(headerKey, rateLimitMetricHeaderPrefix) && !strings.HasPrefix(headerKey, rateLimitRemainingResourceHeader) {
			description := strings.ToLower(strings.TrimPrefix(headerKey, rateLimitMetricHeaderPrefix))
			value, err := strconv.ParseInt(headerValue, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse int from header, header value:%s", headerValue)
			}
			var descriptionTagValue string
			var tenantIDTagValue string
			var subscriptionIDTagValue string
			var resourceTypeTagValue string
			requiredTags, ok := rateLimitDescriptionToRequiredTags[description]
			if !ok {
				return nil, fmt.Errorf("description not found in description to required tags map, description: %s, tags map: %v", description, rateLimitDescriptionToRequiredTags)

			}
			if _, ok := requiredTags[rateLimitRemainingDescriptionTag]; ok {
				descriptionTagValue = description
			}
			if _, ok := requiredTags[rateLimitRemainingTenantIDTag]; ok {
				tenantIDTagValue = m.tenantID
			}
			if _, ok := requiredTags[rateLimitRemainingSubscriptionIDTag]; ok {
				subscriptionIDTagValue = m.subscriptionID
			}
			if _, ok := requiredTags[rateLimitRemainingResourceTypeTag]; ok {
				resourceTypeTagValue = m.resourceType
			}
			ret = append(ret, metricResult{
				TagValues: []string{
					descriptionTagValue,
					tenantIDTagValue,
					subscriptionIDTagValue,
					resourceTypeTagValue,
				},
				Value: float64(value),
			})
		}
	}
	return ret, nil
}

func (m *MetricsExtractor) getRequestLimitResourceMetrics(response *http.Response) ([]metricResult, error) {
	var ret []metricResult
	headerValue := response.Header.Get(rateLimitRemainingResourceHeader)
	if headerValue == "" {
		return nil, nil
	}
	headerValues := strings.Split(headerValue, ",")
	for _, splitHeaderValue := range headerValues {
		split := strings.Split(splitHeaderValue, ";")
		if len(split) != 2 {
			return nil, fmt.Errorf("header value split had unexpected length, expected 2, actual: %d, headerValue: %s", len(split), splitHeaderValue)
		}
		policy := split[0]
		valueString := split[1]
		value, err := strconv.ParseInt(valueString, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse int from header value, headerValue: %s: %w", splitHeaderValue, err)
		}
		ret = append(ret, metricResult{
			TagValues: []string{policy, m.tenantID, m.subscriptionID, m.resourceType},
			Value:     float64(value),
		})
	}
	return ret, nil
}

// Do applies the policy to the specified Request.  When implementing a Policy, mutate the
// request before calling req.Next() to move on to the next policy, and respond to the result
// before returning to the caller.
func (m *MetricsExtractor) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if extractErr := m.extractMetrics(resp); extractErr != nil {
		m.logger.WithError(extractErr).Info("Failed to extract metric")
	}
	return resp, err
}
