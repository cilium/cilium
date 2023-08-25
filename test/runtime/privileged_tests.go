// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

const (
	// The privileged unit tests can take more than 4 minutes, the default
	// timeout for helper commands.
	privilegedUnitTestTimeout = 30 * time.Minute
)

var _ = Describe("RuntimeDatapathPrivilegedUnitTests", func() {

	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		res := vm.ExecWithSudo("systemctl stop cilium")
		res.ExpectSuccess("Failed trying to stop cilium via systemctl")
		ExpectCiliumNotRunning(vm)
	})

	AfterAll(func() {
		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "Failed to restart Cilium")
		vm.CloseSSHClient()
	})

	It("Run Tests", func() {
		path, _ := filepath.Split(vm.BasePath())
		ctx, cancel := context.WithTimeout(context.Background(), privilegedUnitTestTimeout)
		defer cancel()
		res := vm.ExecContext(ctx, fmt.Sprintf("bash -c 'sudo make -C %s tests-privileged NO_COLOR=1 | ts \"[%%H:%%M:%%S]\"; exit \"${PIPESTATUS[0]}\"'", path))
		res.ExpectSuccess("Failed to run privileged unit tests")
	})
})
