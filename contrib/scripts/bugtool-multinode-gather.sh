#!/usr/bin/env bash

# Usage
# ./bugtool-multinode-gather.sh <OUTPUT_DIR> <NAMESPACE> <LABEL> <OUTPUT_ARCHIVE>
#
# Running without arguments is the same as
# 
# ./bugtool-multinode-gather.sh `mktemp -d` kube-system k8s-app=cilium "`mktemp`.tar.gz"

OUTPUT_DIR=${1:-"`mktemp -d`"}
NAMESPACE=${2:-"kube-system"}
LABEL=${3:-"k8s-app=cilium"}
OUTPUT_ARCHIVE=${4:-"`mktemp`.tar.gz"}

mkdir -pv ${OUTPUT_DIR}
function cleanup {
  if [ "${OUTPUT_DIR}" == "/" ]; then
    echo "Aborting cleanup OUTPUT_DIR=${OUTPUT_DIR}"
    exit 0
  fi
  rm -rf ${OUTPUT_DIR}
}
trap cleanup EXIT

for CILIUM in $(kubectl -n ${NAMESPACE} get pods --selector=${LABEL} --output=jsonpath={.items..metadata.name}); do
  BUGTOOL_CMD="cilium-bugtool --archive=false"
  echo "=============== ${CILIUM} ${BUGTOOL_CMD} ==============="
  ARCHIVE=`kubectl exec -n ${NAMESPACE} ${CILIUM} -- ${BUGTOOL_CMD} | grep DIRECTORY | awk '{ print $3}'`
  kubectl cp ${NAMESPACE}/${CILIUM}:${ARCHIVE} ${OUTPUT_DIR}/${CILIUM}
done

tar -cvzf ${OUTPUT_ARCHIVE} ${OUTPUT_DIR} > /dev/null

echo ARCHIVE at ${OUTPUT_ARCHIVE}
