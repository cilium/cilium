#!/bin/bash

set -eu

TOPDIR=$(git rev-parse --show-toplevel)

ineffassign $TOPDIR
