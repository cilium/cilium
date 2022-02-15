#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# This script reads the output of netperf results from Kubernetes upstream
# project and pushes the results to the given Prometheus server.
# Needed variables to run this script:
# - PROMETHEUS_URL: metrics gateway URL, example:
# https://localhost:8080/metrics/job/some_job
# - PROMETHEUS_USR: Prometheus metrics gateway user
# - PROMETHEUS_PSW: Prometheus user password

import csv
import logging
import os
import re
import requests
import sys

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

PROMETHEUS_CONFIG = dict(
    URL="",
    USR="",
    PSW="")


def trim_filename(filename):
    """
    trim_filename:delete all the spaces in the given filename and returns and
    string
    """
    result = []
    space_pattern = re.compile(r"\s")

    with open(filename) as fp:
        for row in fp:
            result.append("{0}\n".format(space_pattern.sub("", row)))
    return result


def read_data(filename):
    """
        read the csv result netperf and return an string with an array with
        key=>value data to push to any metrics system.
    """
    MSS_key = "MSS"
    result = []
    data = trim_filename(filename)

    csv_reader = csv.DictReader(data)
    for row in csv_reader:
        key = re.sub(r"[0-9]", "", row.get(MSS_key))
        for mtu in row.keys():
            if mtu == "" or mtu == MSS_key:
                continue
            val = row.get(mtu)
            if val is None or val == "":
                continue
            result.append(('{0}{{mss="{1}"}}'.format(key, mtu), val))
    logging.info("Retrieved '{0}' metrics".format(len(result)))
    return result


def push_to_prometheus(data):
    """
        it receives a tuple with key value storage and push the info to
        prometheus config server given in the ENV variables
    """
    result = ""
    for metric, value in data:
        metric_key = metric.replace(".", "_")
        result += "{0} {1}\n".format(metric_key, value)
        logging.info("Metric {0} has the value {1}".format(metric_key, value))
    req = requests.post(
        PROMETHEUS_CONFIG.get("URL"),
        data=result,
        auth=(PROMETHEUS_CONFIG.get("USR"), PROMETHEUS_CONFIG.get("PSW")))
    if req.status_code == 202:
        logging.info("Data pushed correctly to prometheus")
        return True
    logging.error(
        "Cannot push data to prometheus:"
        "err='{0.text}' status_code={0.status_code}".format(req))
    return False


if __name__ == "__main__":
    for key, val in PROMETHEUS_CONFIG.items():
        PROMETHEUS_CONFIG[key] = os.environ.get("PROMETHEUS_{0}".format(key))

    if len(sys.argv) == 1:
        logging.error("CSV file to retrieved data is not defined.")
        sys.exit(1)
    try:
        data = read_data(sys.argv[1])
    except os.FileNotFoundError:
        logging.error("{0} cannot be oponened".format(sys.argv[0]))
        sys.exit(1)

    if len(data) == 0:
        logging.error("No data was retrieved")
        sys.exit(1)
    push_to_prometheus(data)
