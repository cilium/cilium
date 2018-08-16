#!/bin/bash

set -eux

TOPDIR=$(git rev-parse --show-toplevel)

ineffassign $TOPDIR
