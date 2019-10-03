#!/bin/bash

set -e

hostname -I | awk '{print $1}'
