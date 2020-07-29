#!/usr/bin/env python3

"""
This script requires PyGithub to be installed
`pip install pygithub`

GITHUB_TOKEN env variable is used to access GH API
"""

import argparse
import os
import sys

try:
    from github import Github
except ImportError:
    print("pygithub not found you can install it by running 'pip3 install --user PyGithub'")
    sys.exit(-1)

parser = argparse.ArgumentParser()
parser.add_argument('pr_number', type=int)
actions = ["pending", "done"]
parser.add_argument('action', type=str, choices=actions)
parser.add_argument('version', type=str, default="1.0", nargs='?')

args = parser.parse_args()

token = os.environ["GITHUB_TOKEN"]
pr_number = args.pr_number
action = args.action
version = args.version

g = Github(token)
cilium = g.get_repo("cilium/cilium")
pr = cilium.get_pull(pr_number)
pr_labels = list(pr.get_labels())
old_label_len = len(pr_labels)

cilium_labels = cilium.get_labels()

print("Setting labels for PR {}... ".format(pr_number), end="")
if action == "pending":
    pr_labels = [l for l in pr_labels
                 if l.name != "needs-backport/"+version]
    if old_label_len - 1 != len(pr_labels):
        print("needs-backport/"+version+" label not found in PR, exiting")
        sys.exit(1)

    pr_labels.append(
        [l for l in cilium_labels if l.name == "backport-pending/"+version][0])

    if old_label_len != len(pr_labels):
        print("error adding backport-pending/"+version+" label to PR, exiting")
        sys.exit(2)
    pr.set_labels(*pr_labels)

if action == "done":
    pr_labels = [l for l in pr_labels
                 if l.name != "backport-pending/"+version]
    if old_label_len - 1 != len(pr_labels):
        print("backport-pending/"+version+" label not found in PR, exiting")
        sys.exit(1)

    pr_labels.append(
        [l for l in cilium_labels if l.name == "backport-done/"+version][0])

    if old_label_len != len(pr_labels):
        print("error adding backport-done/"+version+" label to PR, exiting")
        sys.exit(2)
    pr.set_labels(*pr_labels)

print("✓")
