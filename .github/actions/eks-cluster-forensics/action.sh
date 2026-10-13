#!/usr/bin/env bash
# Each probe may fail on its own, so this script runs without -e.

set -u

ARTIFACTS_SUFFIX="${1:?artifacts_suffix argument is required}"
PHASE="${2:-post}"
CLUSTER_NAME="${CLUSTER_NAME:?CLUSTER_NAME is required}"
NODE_BASELINE="${NODE_BASELINE:-}"

OUT="$(mktemp -d)"
START_TIME="$(date -u -d '12 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
echo "Collecting EKS cluster forensics for ${CLUSTER_NAME} into ${OUT}"

# Name of the role this job runs as, which the artifact must not carry.
CI_ROLE="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null |
  sed -n 's|^arn:aws:sts::[0-9]*:assumed-role/\([A-Za-z0-9+=,.@_-]*\)/.*|\1|p')"

kubectl get nodes -o wide --request-timeout=60s > "${OUT}/nodes.txt" 2>&1
kubectl get nodes -o json --request-timeout=60s > "${OUT}/nodes.json" 2>&1
kubectl get events -A --sort-by=.lastTimestamp --request-timeout=60s > "${OUT}/events.txt" 2>&1
kubectl get ciliumnodes -o json --request-timeout=60s > "${OUT}/ciliumnodes.json" 2>&1

aws eks describe-cluster --name "${CLUSTER_NAME}" > "${OUT}/eks-describe-cluster.json" 2>&1
VPC_ID="$(jq -r '.cluster.resourcesVpcConfig.vpcId // empty' "${OUT}/eks-describe-cluster.json" 2>/dev/null)"
mapfile -t SUBNET_IDS < <(jq -r '.cluster.resourcesVpcConfig.subnetIds[]?' "${OUT}/eks-describe-cluster.json" 2>/dev/null)

{
  echo "cluster=${CLUSTER_NAME}"
  echo "region=${AWS_REGION:-}"
  echo "vpc=${VPC_ID}"
  echo "phase=${PHASE}"
  echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cloudtrail_start_time=${START_TIME}"
} > "${OUT}/context.txt"

if [ "${#SUBNET_IDS[@]}" -gt 0 ]; then
  aws ec2 describe-subnets --subnet-ids "${SUBNET_IDS[@]}" > "${OUT}/ec2-describe-subnets.json" 2>&1
fi
if [ -n "${VPC_ID}" ]; then
  aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" \
    > "${OUT}/ec2-describe-network-interfaces.json" 2>&1
fi

aws eks list-nodegroups --cluster-name "${CLUSTER_NAME}" > "${OUT}/eks-list-nodegroups.json" 2>&1
for ng in $(jq -r '.nodegroups[]?' "${OUT}/eks-list-nodegroups.json" 2>/dev/null); do
  aws eks describe-nodegroup --cluster-name "${CLUSTER_NAME}" --nodegroup-name "${ng}" \
    > "${OUT}/eks-describe-nodegroup-${ng}.json" 2>&1
  for asg in $(jq -r '.nodegroup.resources.autoScalingGroups[]?.name' "${OUT}/eks-describe-nodegroup-${ng}.json" 2>/dev/null); do
    aws autoscaling describe-scaling-activities --auto-scaling-group-name "${asg}" \
      > "${OUT}/asg-activities-${asg}.json" 2>&1
  done
done

# A deleted stack only answers to its stack id.
aws cloudformation list-stacks --query "StackSummaries[?starts_with(StackName, 'eksctl-${CLUSTER_NAME}-')]" \
  > "${OUT}/cfn-list-stacks.json" 2>&1
for stack_id in $(jq -r '.[].StackId' "${OUT}/cfn-list-stacks.json" 2>/dev/null); do
  aws cloudformation describe-stacks --stack-name "${stack_id}" \
    > "${OUT}/cfn-describe-stack-${stack_id##*/}.json" 2>&1
  aws cloudformation describe-stack-events --stack-name "${stack_id}" \
    > "${OUT}/cfn-stack-events-${stack_id##*/}.json" 2>&1
done

# The baseline also names the instances that no longer have a Node object.
{
  jq -r '.items[].spec.providerID // empty' "${OUT}/nodes.json" 2>/dev/null
  [ -r "${NODE_BASELINE}" ] && jq -r '.items[].spec.providerID // empty' "${NODE_BASELINE}" 2>/dev/null
} | sed -n 's|.*/\(i-[0-9a-f]*\)$|\1|p' | sort -u > "${OUT}/instance-ids.txt"
if [ -s "${OUT}/instance-ids.txt" ]; then
  aws ec2 describe-instances --filters "Name=instance-id,Values=$(paste -sd, "${OUT}/instance-ids.txt")" \
    > "${OUT}/ec2-describe-instances.json" 2>&1
fi

ids="$({
  echo "${CLUSTER_NAME}"
  printf '%s\n' "${SUBNET_IDS[@]}"
  cat "${OUT}/instance-ids.txt"
  jq -r '.NetworkInterfaces[]?.NetworkInterfaceId' "${OUT}/ec2-describe-network-interfaces.json" 2>/dev/null
} | grep -x '[A-Za-z0-9_-]\+' | paste -sd'|')"
own='^$'
[ -n "${ids}" ] && own="(^|[^A-Za-z0-9_-])(${ids})([^A-Za-z0-9_-]|\$)"

# Anyone can download the artifact, so an event keeps no caller identity beyond ciRole.
# shellcheck disable=SC2016
events='[.Events[]?.CloudTrailEvent | fromjson? | select(tostring | test($own)) | {
  eventTime, eventSource, eventName, errorCode,
  userType: .userIdentity.type,
  invokedBy: .userIdentity.invokedBy,
  ciRole: ($role != "" and .userIdentity.sessionContext.sessionIssuer.userName == $role),
  requestParameters
}]'

# Usage: lookup <file name> <ownership regex> <lookup attribute>
lookup() {
  aws cloudtrail lookup-events --max-items 250 --start-time "${START_TIME}" --lookup-attributes "$3" \
    </dev/null 2>"${OUT}/$1.err" |
    jq --arg own "$2" --arg role "${CI_ROLE}" "${events}" > "${OUT}/$1.json" 2>>"${OUT}/$1.err"
}

while read -r instance_id; do
  lookup "cloudtrail-resource-${instance_id}" . "AttributeKey=ResourceName,AttributeValue=${instance_id}"
done < "${OUT}/instance-ids.txt"
lookup cloudtrail-resource-cluster . "AttributeKey=ResourceName,AttributeValue=${CLUSTER_NAME}"
# The account-wide events keep only those that name this cluster's resources.
for event in DeleteNodegroup DeleteCluster DeleteStack DeleteSubnet TerminateInstances \
  AssignPrivateIpAddresses UnassignPrivateIpAddresses; do
  lookup "cloudtrail-event-${event}" "${own}" "AttributeKey=EventName,AttributeValue=${event}"
done

# Strip the account ID and the CI role name from every file.
redact=(-e 's/\b[0-9]{12}\b/<account>/g')
role_re="${CI_ROLE//./\\.}"
[ -n "${CI_ROLE}" ] && redact+=(-e "s/${role_re//+/\\+}/<ci-role>/g")
find "${OUT}" -name '*.err' -empty -delete
find "${OUT}" -type f -exec sed -i -E "${redact[@]}" {} +

TARBALL="${GITHUB_WORKSPACE:-.}/eks-cluster-forensics-${ARTIFACTS_SUFFIX}-${PHASE}.tar.gz"
tar -czf "${TARBALL}.tmp" -C "${OUT}" . && mv "${TARBALL}.tmp" "${TARBALL}"
rm -rf "${OUT}"
echo "Wrote ${TARBALL}"
