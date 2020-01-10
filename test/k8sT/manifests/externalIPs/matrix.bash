#!/usr/bin/env bash

function run_matrix_tests(){
        cmd="${1}"
        ips="${2}"
        ports="${3}"
        numeric="${4}"
        headers="${5}"
        for ipName in ${ips}; do
                ipNameArr=(${ipName//=/ })
                hostName=${ipNameArr[0]}
                ip=${ipNameArr[1]}
                for portName in ${ports}; do
                     portNameArr=(${portName//=/ })
                     protoName=${portNameArr[0]}
                     port=${portNameArr[1]}
                     if [[ -n "${headers}" ]]; then
                             if [[ -n "${numeric}" ]]; then
                                printf "%s %-22s %s -> " "curl" "${ip}:${port}"
                             else
                                printf "%s\t%s\t" "${hostName}" "${protoName}"
                             fi
                     fi
                     output=$(${cmd} ${ip}:${port} 2>&1);
                     if echo "${output}" | grep -q 'Guestbook' ; then
                        echo "app1"
                     elif echo "${output}" | grep -q 'Connection refused' ; then
                        echo "connection refused"
                     elif echo "${output}" | grep -q 'No route to host' ; then
                        echo "No route to host"
                     elif echo "${output}" | grep -q "It works!" ; then
                        echo "app2"
                     elif echo "${output}" | grep -q "Connection timed out" ; then
                        echo "connection timed out"
                     else
                        echo "None? ${output}"
                     fi
                done
        done
}

while getopts ":g:i:p:c:nHh" opt
   do
     case ${opt} in
        i ) ips=${OPTARG};;
        p ) ports=${OPTARG};;
        c ) client_container=${OPTARG};;
        n ) numeric="true";;
        H ) headers="true";;
        g ) namespace=${OPTARG};;
        h ) help="true";;

     esac
done

if [[ -n "${help}" ]]; then
        echo "matrih.bash"
        echo ""
        echo "matrix.bash executes curl for all combinations of the given ports and IPv4 addresses!"
        echo ""
        echo "Run 'matrix.bash -g <k8s-namespace>' to get the an example of a command that you need to run"
        echo "As a tip, it's useful to execute with -H to get the columns descriptions, for the follow up"
        echo "tests omit the '-H' so you can copy-paste the result quicker as the combinations of ip-ports"
        echo "is always consistent."
        echo "Flags:"
        echo " -g <namespace> (connects to kubernetes to derive all the service and ports going to be tested)"
        echo " -i \"<name-1>=<ip-1> <name-2>=<ip-2>\" (list of IP addresses)"
        echo " -p \"<port-name-1>=<port-1> <port-name-2>=<port-2>\" (list of ports)"
        echo " -c <containerID> (It executes the curl commands with nsenter inside the given container ID"
        echo " -n (prints the numeric value of the IPs being used instead the names)"
        echo " -H (if set, prints the columns with the description for which the request is being executed to)"
        echo " -h (prints this message)"
        exit 0;
fi

if [[ -n "${namespace}" ]]; then
        svc_ports=$(kubectl get svc -n ${namespace} -o jsonpath="{range .items[*]}{.metadata.name}{'-svc-port='}{.spec.ports[*].port}{'\n'}{end}")
        node_port_ports=$(kubectl get svc -n ${namespace} -o jsonpath="{range .items[*]}{.metadata.name}{'-node-port='}{.spec.ports[*].nodePort}{'\n'}{end}")

        for port in ${svc_ports} ${node_port_ports}; do
                portNameArr=(${port//=/ })
                portNumber=${portNameArr[1]}
                if [[ -n "${portNumber}" ]]; then
                      ports_str+="${port} "
                fi
        done
        svcs=$(kubectl get svc -n ${namespace} -o jsonpath="{range .items[*]}{.metadata.name}{'-cluster-ip='}{.spec.clusterIP}{'\n'}{end}")
        svcs_str="svc-a-external-ips-k8s1-public=192.0.2.233 svc-a-external-ips-k8s1-host-public=192.168.34.11 svc-a-external-ips-k8s1-host-private=192.168.33.11\
                  svc-b-external-ips-k8s1-public=192.0.2.233 svc-b-external-ips-k8s2-host-public=192.168.34.11 svc-b-external-ips-k8s1-host-private=192.168.33.11\
                  localhost=127.0.0.1 "

        for svc in ${svcs}; do
              svcs_str+="${svc} "
        done
        printf './matrix.bash -i "%s" -p "%s"\n' "${svcs_str}" "${ports_str}"
        exit 0;
fi

curl_cmd="curl --connect-timeout 2 -vs"

echo "Running from host"
run_matrix_tests "${curl_cmd}" "${ips}" "${ports}" "${numeric}" "${headers}"
if [[ -n "${client_container}" ]]; then
        PID=$(docker inspect --format '{{.State.Pid}}' ${client_container})
        echo "Running from container ${client_container}"
        cmd="sudo nsenter --target ${PID} --uts --ipc --net --pid"
        run_matrix_tests "${cmd} ${curl_cmd}" "${ips}" "${ports}" "${numeric}" "${headers}"
fi
