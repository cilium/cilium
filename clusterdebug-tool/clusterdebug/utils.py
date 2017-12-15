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

import sys
import subprocess
import logging

FORMAT = '%(levelname)s %(message)s'
# TODO: Make the logging level configurable.
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=FORMAT)
if sys.stdout.isatty():
    # running in a real terminal
    # Color code source: http://bit.ly/2zPHiCK
    logging.addLevelName(
        logging.WARNING,
        "\033[1;31m%s\033[1;0m" %
        logging.getLevelName(
            logging.WARNING))
    logging.addLevelName(
        logging.ERROR,
        "\033[1;31m%s\033[1;0m" %
        logging.getLevelName(
            logging.ERROR))
log = logging.getLogger(__name__)


class ModuleCheck:
    """Checks whether the module conforms to a certain state.

    Args:
        summary (string): A summary of what the check does.
        check_cb (callback): A callback function for performing the check.
    """

    def __init__(
            self,
            summary,
            check_cb):
        self.name = summary
        self.check_cb = check_cb

    def success_cb(self):
        """Default callback function to call when the ModuleCheck succeeds."""
        # TODO: Perform additional actions (like storing debug data in S3)
        log.info("-- Success --\n")
        return

    def failure_cb(self):
        """Default callback function to call when the ModuleCheck fails."""
        # TODO: Perform additional actions (like storing debug data in S3)
        log.error("-- Failure --\n")
        return

    def get_title(self):
        return "-- " + self.name + " --"

    def run(self):
        log.info(self.get_title())
        if not self.check_cb():
            self.failure_cb()
            return False
        else:
            self.success_cb()
            return True


class ModuleCheckGroup:
    """Ordered list of ModuleChecks

    Runs the ModuleChecks in order. If a ModuleCheck fails, the ModuleChecks
     after that ModuleCheck would not be executed.

    Args:
        name (string): the name of the group of ModuleChecks.
        checks (list): the list of ModuleCheck objects.
    """

    def __init__(self, name, checks=None):
        self.name = name
        self.checks = checks

    def get_title(self):
        return "== " + self.name + " =="

    def add(self, check):
        if self.checks is None:
            self.checks = []
        self.checks.append(check)
        return self

    def run(self):
        log.info(self.get_title())
        for check in self.checks:
            if not check.run():
                return


def get_nodes():
    """Returns a list of nodes. """
    COMMAND = "kubectl get nodes | grep -v NAME | awk '{print $1}'"
    try:
        output = subprocess.check_output(COMMAND, shell=True)
    except subprocess.CalledProcessError as grepexc:
        log.error("error code: ", grepexc.returncode, grepexc.output)
        return []
    return output.splitlines()


def get_pod_config(pod_name):
    """Returns the pod config of a k8s pod with name pod_name. """
    COMMAND = "kubectl describe pod " + pod_name + " -n kube-system"
    try:
        output = subprocess.check_output(COMMAND, shell=True)
    except subprocess.CalledProcessError as grepexc:
        log.error("error code: ", grepexc.returncode, grepexc.output)
        return None
    if output == "":
        log.error("could not get pod configuration.")
    return output


def get_pods_status_iterator(pod_name_substring, must_exist=True):
    """Returns an iterator to the status of pods.

    Args:
        pod_name_substring - the substring containing the pod name.
        must_exist - boolean to indicate that a pod with that name must exist.
            If the condition isn't satisfied, an error will be logged.

    Returns:
        name (string): name of the pod.
        ready_status (string): the ready status of the pod.
        status (string): the status of the pod (e.g. Running).
        node_name (string): the name of the node.
    """
    cmd = "kubectl get pods -o wide --all-namespaces " \
          "| grep " + pod_name_substring + " | " \
          "awk '{print $2 \" \" $3 \" \" $4 \" \" $NF}'"
    output = ""
    try:
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as exc:
        log.error("command to get status of {} has "
                  "failed. error code: "
                  "{} {}".format(pod_name_substring,
                                 exc.returncode, exc.output))
        return
    if output == "":
        if must_exist:
            log.error("no {} pods are running on the cluster".format(
                pod_name_substring))
        return
    for line in output.splitlines():
        # Example line:
        # name-blah-sr64c 0/1 CrashLoopBackOff
        # ip-172-0-33-255.us-west-2.compute.internal
        split_line = line.split(' ')
        yield split_line[0], split_line[1], split_line[2], split_line[-1]
