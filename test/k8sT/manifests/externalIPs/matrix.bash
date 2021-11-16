#!/usr/bin/env bash

function run_matrix_tests(){
        cmd="${1}"
        ips="${2}"
        ports="${3}"
        numeric="${4}"
        headers="${5}"
        golang="${6}"
        filename="${7}"
        for ipName in ${ips}; do
                ipNameArr=(${ipName//=/ })
                hostName=${ipNameArr[0]}
                if [[ -n "${golang}" ]]; then
                    printf '\t\t"%s": {\n' "${hostName}" >> "${filename}"
                fi
                ip=${ipNameArr[1]}
                for portName in ${ports}; do
                     portNameArr=(${portName//=/ })
                     protoName=${portNameArr[0]}
                     port=${portNameArr[1]}
                     if [[ -n "${golang}" ]]; then
                         printf '\t\t\t"%s": {\n' "${protoName}" >> "${filename}"
                         printf '\t\t\t\tDescription: "%s",\n' "${hostName}:${protoName}" >> "${filename}"
                         printf '\t\t\t\tIP:          "%s",\n' "${ip}" >> "${filename}"
                         printf '\t\t\t\tPort:        "%s",\n' "${port}" >> "${filename}"
                     elif [[ -n "${headers}" ]]; then
                             if [[ -n "${numeric}" ]]; then
                                printf "%s %-22s %s -> " "curl" "${ip}:${port}"
                             else
                                printf "%s\t%s\t" "${hostName}" "${protoName}"
                             fi
                     fi
                     output=$(${cmd} ${ip}:${port} 2>&1);
                     if echo "${output}" | grep -q 'Guestbook' ; then
                        result="app1"
                     elif echo "${output}" | grep -q 'Connection refused' ; then
                        result="connection refused"
                     elif echo "${output}" | grep -qE '(No route to host)|(Host is unreachable)|(Connection timed out)' ; then
                        result="No route to host / connection timed out"
                     elif echo "${output}" | grep -q "It works!" ; then
                        result="app2"
                     elif echo "${output}" | grep -q "app4" ; then
                        result="app4"
                     elif echo "${output}" | grep -q "app6" ; then
                        result="app6"
                     else
                        result="None? ${output}"
                     fi
                     if [[ -n "${golang}" ]]; then
                        printf '\t\t\t\tExpected:    "%s",\n' "${result}" >> "${filename}"
                        printf '\t\t\t},\n' >> "${filename}"
                     else
                        echo "${result}"
                     fi
                done
                if [[ -n "${golang}" ]]; then
                     printf '\t\t},\n' >> "${filename}"
                fi
        done
}

while getopts ":g:i:p:c:nHhG" opt
   do
     case ${opt} in
        i ) ips=${OPTARG};;
        p ) ports=${OPTARG};;
        c ) client_pods=${OPTARG};;
        n ) numeric="true";;
        G ) golang="true";;
        H ) headers="true";;
        g ) namespace=${OPTARG};;
        h ) help="true";;

     esac
done

if [[ -n "${help}" ]]; then
        echo "matrix.bash"
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
        echo " -c \"<name-1>=<ip-1> <name-2>=<ip-2>\" (list of IP addresses)"
        echo " -n (prints the numeric value of the IPs being used instead the names)"
        echo " -H (if set, prints the columns with the description for which the request is being executed to)"
        echo " -G (if set, prints in golang code)"
        echo " -h (prints this message)"
        exit 0;
fi

if [[ -n "${namespace}" && -z "${ips}" ]]; then
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
        svcs_str="svc-a-external-ips-k8s1-public=192.0.2.233 svc-a-external-ips-k8s1-host-public=192.168.34.11 svc-a-external-ips-k8s1-host-private=192.168.33.11 \
svc-b-external-ips-k8s1-public=192.0.2.233 svc-b-external-ips-k8s1-host-public=192.168.34.11 svc-b-external-ips-k8s1-host-private=192.168.33.11 \
localhost=127.0.0.1 "

        for svc in ${svcs}; do
              svcs_str+="${svc} "
        done
        cmd=$(kubectl get pod -n "${namespace}" -l id=host-client -o jsonpath='{.items[?(@.spec.nodeName=="k8s1")].metadata.name}')
        client_pods="node_to_node.go=ExpectedResultFromNode1=${cmd}"
        cmd=$(kubectl get pod -n "${namespace}" -l id=host-client -o jsonpath='{.items[?(@.spec.nodeName=="k8s2")].metadata.name}')
        client_pods+=" other_node_to_node.go=ExpectedResultFromNode2=${cmd}"

        cmd=$(kubectl get pod -n "${namespace}" -l id=app3 -o jsonpath='{.items[*].metadata.name}')
        client_pods+=" pod_other_node_to_node.go=ExpectedResultFromPodInNode2=${cmd}"
        cmd=$(kubectl get pod -n "${namespace}" -l id=app1 -o jsonpath='{.items[*].metadata.name}')
        client_pods+=" pod_to_node.go=ExpectedResultFromPodInNode1=${cmd}"
        printf './matrix.bash -g "%s" -i "%s" -p "%s" -G -c "%s" \n' "${namespace}" "${svcs_str}" "${ports_str}" "${client_pods}"
        exit 0;
fi

curl_cmd="curl --connect-timeout 2 -vs"

for client_pod in ${client_pods}; do
        clientPodArr=(${client_pod//=/ })
        filename=${clientPodArr[0]}
        test_name=${clientPodArr[1]}
        pod_name=${clientPodArr[2]}
        if [[ -n "${golang}" ]]; then
                printf '// Copyright 2020 Authors of Cilium\n' > "${filename}"
                printf '//\n' >> "${filename}"
                printf '// Licensed under the Apache License, Version 2.0 (the "License");\n' >> "${filename}"
                printf '// you may not use this file except in compliance with the License.\n' >> "${filename}"
                printf '// You may obtain a copy of the License at\n' >> "${filename}"
                printf '//\n' >> "${filename}"
                printf '//     http://www.apache.org/licenses/LICENSE-2.0\n' >> "${filename}"
                printf '//\n' >> "${filename}"
                printf '// Unless required by applicable law or agreed to in writing, software\n' >> "${filename}"
                printf '// distributed under the License is distributed on an "AS IS" BASIS,\n' >> "${filename}"
                printf '// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n' >> "${filename}"
                printf '// See the License for the specific language governing permissions and\n' >> "${filename}"
                printf '// limitations under the License.\n' >> "${filename}"
                printf '\n' >> "${filename}"
                printf 'package external_ips\n\n' >> "${filename}"
                printf 'var (\n' >> "${filename}"
                printf '\t%s = map[string]map[string]EntryTestArgs{\n' "${test_name}" >> "${filename}"
        fi
        run_matrix_tests "kubectl exec -n ${namespace} ${pod_name} -c curl -- ${curl_cmd}" "${ips}" "${ports}" "${numeric}" "${headers}" "${golang}" "${filename}"
        if [[ -n "${golang}" ]]; then
                printf '\t}\n)\n' >> "${filename}"
        fi
done
