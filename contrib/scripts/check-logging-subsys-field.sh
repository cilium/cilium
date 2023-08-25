#!/usr/bin/env bash

# check-logging-subsys-field.sh checks whether all logging entry instancs
# created from DefaultLogger contain the LogSubsys field. This is required for
# proper labeling of error/warning Prometheus metric and helpful for debugging.
# If any entry which writes any message doesn't contaion the 'subsys' field,
# Prometheus metric logging hook (`pkg/metrics/logging_hook.go`) is going to
# fail.

# Directories:
# - pkg/debugdetection
# - test/
# - vendor/
# - _build/
# are excluded, because instances of DefaultLogger in those modules have their
# specific usage which doesn't break the Prometheus logging hook.

set -eu

if grep -IPRns '(?!.*LogSubsys)log[ ]*= logging\.DefaultLogger.*' \
        --exclude-dir={.git,_build,vendor,test,pkg/debugdetection} \
        --include=*.go .; then
    echo "Logging entry instances have to contain the LogSubsys field. Example of"
    echo "properly configured entry instance:"
    echo
    echo -e "\timport ("
    echo -e "\t\t\"github.com/cilium/cilium/pkg/logging\""
    echo -e "\t\t\"github.com/cilium/cilium/pkg/logging/logfields\""
    echo -e "\t)"
    echo
    echo -e "\tvar log = logging.DefaultLogger.WithField(logfields.LogSubsys, \"my-subsystem\")"
    echo
    exit 1
fi
