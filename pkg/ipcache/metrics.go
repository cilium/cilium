// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

var (
	metricTypeUpsert  = "upsert"
	metricTypeDelete  = "delete"
	metricTypeRecover = "recover"

	metricErrorIdempotent = "idempotent_operation"
	metricErrorInvalid    = "invalid_prefix"
	metricErrorNoExist    = "no_such_prefix"
	metricErrorOverwrite  = "cannot_overwrite_by_source"
	metricErrorUnexpected = "upsert_unexpectedly_deleted_entry"
)
