//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/cilium-cli/cli"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/test/cilium-cli/tests"
)

const (
	testAllowAllExceptWorld = "allow-all-except-world"
)

// CLIHooks implements cli.Hooks interface to add connectivity tests.
type CLIHooks struct {
	cli.NopHooks
}

// AddConnectivityTests registers connectivity tests.
func (eh *CLIHooks) AddConnectivityTests(ct *check.ConnectivityTest) error {
	test := ct.MustGetTest(testAllowAllExceptWorld)
	test.WithScenarios(tests.PolicyVerdict())
	return nil
}
