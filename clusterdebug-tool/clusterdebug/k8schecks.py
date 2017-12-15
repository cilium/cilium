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

import subprocess
import utils
import re
import logging
log = logging.getLogger(__name__)


def check_kube_apiserver_version_cb():
    """Checks the version of the active kube-apiserver.

    Args:
        none

    Returns:
        True if successful, False otherwise.
    """
    p = re.compile(
        "^Server Version: version.Info{Major:\"(\d+)\", Minor:\"(\d+)\".*$")

    cmd = "kubectl version"
    try:
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as exc:
        log.error(
            "command to check API server version has failed."
            " error code: {} {}".format(
                exc.returncode,
                exc.output))
        return False
    else:
        for line in output.splitlines():
            match = p.search(line)
            if match:
                major_version = int(match.group(1))
                minor_version = int(match.group(2))
                if major_version != 1 or (
                    major_version == 1 and
                        (minor_version < 7 or minor_version > 8)):
                    log.error("the kube-apiserver version is {}.{}. "
                              "We need a version >= 1.7 or <= 1.8.".format(
                                  major_version, minor_version))
                    return False
                else:
                    log.info("the kube-apiserver version is {}.{}".format(
                        major_version, minor_version))
                    return True
        log.warning("could not detect the kube-apiserver version")
        return False


def check_rbac_cb():
    """Checks whether RBAC is enabled on all the kube-apiservers.

    Args:
        None

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    for name, ready_status, status, node_name in \
            utils.get_pods_status_iterator("kube-apiserver-", False):
        cmd = "kubectl describe pod " + name + \
              " -n kube-system"
        try:
            output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            log.error(
                "command to check kube-apiserver pod configuration has failed."
                "error code: {} {}".format(
                    exc.returncode,
                    exc.output))
            ret_code = False
        else:
            if "--authorization-mode=RBAC" in output or \
                    "--authorization-mode=ABAC" in output:
                log.info("RBAC is enabled on the cluster")
            else:
                log.info("RBAC has been disabled on this cluster")
    return ret_code
