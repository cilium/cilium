#!/usr/bin/env bash

# This tests:
# - L7 stress test
# - Policies across k8s namespaces
#
############### Architecture ###############
#
#  Frontend   ----->  Backend
#
# Backend has a service exposed on port 80.
# This test will run a stress test without any L7 policy loaded, after the
# stress test is completed, it will install a policy and run the stress test
# one more time.

set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

l7_stresstest_dir="${dir}/deployments/l7-stresstest"

# Set frontend on k8s-1 to force inter-node communication
node_selector="k8s-1"

sed "s/\$kube_node_selector/${node_selector}/" \
    "${l7_stresstest_dir}/1-frontend.json.sed" > "${l7_stresstest_dir}/1-frontend.json"

# Set backend on k8s-2 to force inter-node communication
# FIXME FIXME FIXME replace with k8s-2 when the l3 + l7 policies are working
node_selector="k8s-1"

sed "s/\$kube_node_selector/${node_selector}/" \
    "${l7_stresstest_dir}/2-backend-server.json.sed" > "${l7_stresstest_dir}/2-backend-server.json"

# Create the namespaces before creating the pods
kubectl create namespace qa
kubectl create namespace development

kubectl create -f "${l7_stresstest_dir}"

kubectl get pods -n qa -o wide
kubectl get pods -n development -o wide

wait_for_running_pod frontend qa
wait_for_running_pod backend development

wait_for_service_endpoints_ready development backend 80
# frontend doesn't have any endpoints

frontend_pod=$(kubectl get pods -n qa | grep frontend | awk '{print $1}')
backend_pod=$(kubectl get pods -n development | grep backend | awk '{print $1}')

backend_svc_ip=$(kubectl get svc -n development | awk 'NR==2{print $2}')

echo "Running tests WITHOUT Policy / Proxy loaded"
#FIXME uncomment once we figure out the right policy for the stresstests
#kubectl exec -n qa -i ${frontend_pod} -- wrk -t20 -c1000 -d60 "http://${backend_svc_ip}:80/"
#kubectl exec -n qa -i ${frontend_pod} -- ab -r -n 1000000 -c 200 -s 60 -v 1 "http://${backend_svc_ip}:80/"

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/)

if [ ${code} -ne 200 ]; then abort "Error: unable to connect between frontend and backend" ; fi

kubectl create -f "${l7_stresstest_dir}/policies"

wait_all_k8s_regenerated

#FIXME uncomment once we figure out the right policy for the stresstests
echo "Running tests WITH Policy / Proxy loaded"
#kubectl exec -n qa -i ${frontend_pod} -- wrk -t20 -c1000 -d60 "http://${backend_svc_ip}:80/"
#kubectl exec -n qa -i ${frontend_pod} -- ab -r -n 1000000 -c 200 -s 60 -v 1 "http://${backend_svc_ip}:80/"

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/)

if [ ${code} -ne 200 ]; then abort "Error: unable to connect between frontend and backend" ; fi

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/health)

if [ ${code} -ne 403 ]; then abort "Error: unexpected connection between frontend and backend. wanted HTTP 403, got: HTTP ${code}" ; fi


echo "SUCCESS!"

kubectl delete -f "${l7_stresstest_dir}/"

kubectl delete -f "${l7_stresstest_dir}/policies"

kubectl delete namespace qa development

set +e

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=l7-stresstest 2>/dev/null

if [ $? -eq 0 ]; then abort "l7-stresstest policy found in cilium; policy should have been deleted" ; fi

