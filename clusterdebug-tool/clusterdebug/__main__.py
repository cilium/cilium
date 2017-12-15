#!/usr/bin/env python
# Copyright 2017 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import utils
import ciliumchecks
import k8schecks
import logging
log = logging.getLogger(__name__)

if __name__ == "__main__":
    nodes = utils.get_nodes()

    k8s_check_grp = utils.ModuleCheckGroup("k8s")
    k8s_check_grp.add(
        utils.ModuleCheck(
            "check the kube-apiserver version",
            lambda: k8schecks.check_kube_apiserver_version_cb()))
    k8s_check_grp.add(
        utils.ModuleCheck(
            "check RBAC configuration",
            lambda: k8schecks.check_rbac_cb()))
    k8s_check_grp.run()

    cilium_check_grp = utils.ModuleCheckGroup("cilium")
    cilium_check_grp.add(
        utils.ModuleCheck(
            "check whether pod is running",
            lambda: ciliumchecks.check_pod_running_cb(nodes)))
    cilium_check_grp.add(
        utils.ModuleCheck(
            "check the access log parameter",
            lambda: ciliumchecks.check_access_log_config_cb()))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether DropNotification is enabled",
        lambda: ciliumchecks.check_drop_notifications_enabled_cb()))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether TraceNotification is enabled",
        lambda: ciliumchecks.check_trace_notifications_enabled_cb()))
    cilium_check_grp.run()
