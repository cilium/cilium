# Test connectivity of VxLAN-in-ESP by ping from $local_node host to pods on $remote_node.

set -ex

test_vxlan_in_esp() {
    local local_node=$1
    local remote_node=$2

    local local_pod_ip=$(kubectl get pods -A --field-selector spec.nodeName=$local_node --output=custom-columns="NAMESPACE:.metadata.namespace,IP:.status.podIP" | awk '/cilium-test/ {print $2; exit}')
    local remote_pod_ip=$(kubectl get pods -A --field-selector spec.nodeName=$remote_node --output=custom-columns="NAMESPACE:.metadata.namespace,IP:.status.podIP" | awk '/cilium-test/ {print $2; exit}')
     # remote_pod_mac doesn't matter, after all it changes during routing
    local remote_pod_mac=3A:73:24:77:70:E9

    local local_host_ip=$(docker exec $local_node ip -4 --br a sh eth0 | grep -oP '\d+\.\d+\.\d+\.\d+')
    local remote_host_ip=$(docker exec $remote_node ip -4 --br a sh eth0 | grep -oP '\d+\.\d+\.\d+\.\d+')
    local local_internal_ip=$(docker exec $local_node ip -4 --br a sh cilium_host | grep -oP '\d+\.\d+\.\d+\.\d+')
    local remote_internal_ip=$(docker exec $remote_node ip -4 --br a sh cilium_host | grep -oP '\d+\.\d+\.\d+\.\d+')
    local encrypt_mark=$(docker exec $local_node ip -4 x p | grep "tmpl src $local_internal_ip dst $remote_internal_ip" -B1 | grep -Po '0x[^/]+e00')

    # 0. setup vxlan0 on $local_node

    docker exec $local_node ip l d vxlan0 || true
    docker exec $local_node ip l a vxlan0 type vxlan id 233 local $local_host_ip dev eth0 dstport 8472 nolearning
     # set down cilium_vxlan, otherwise vxlan0 can't be up
    docker exec $local_node ip l s cilium_vxlan down
    docker exec $local_node ip l s vxlan0 up
     # set a local pod ip to vxlan0, so even ICMP from host has a pod ip as source
    docker exec $local_node ip a r $local_pod_ip/32 dev vxlan0

    # 1. ensure ICMP from $local_node host can be routed to vxlan0
    docker exec $local_node ip r r $remote_pod_ip/32 dev vxlan0
    docker exec $local_node ip n r $remote_pod_ip lladdr $remote_pod_mac dev vxlan0 nud permanent

    # 2. ensure VxLAN uses proper outer IPs
    docker exec $local_node bridge fdb r $remote_pod_mac dst $remote_host_ip dev vxlan0

    # 3. ensure ICMP has proper mark for ESP encryption
    docker exec $local_node iptables -t mangle -D OUTPUT -p udp --dport 8472 -j MARK --set-mark $encrypt_mark || true
    docker exec $local_node iptables -t mangle -A OUTPUT -p udp --dport 8472 -j MARK --set-mark $encrypt_mark

    # 4. ensure xfrm policy out is set
     # btw. xfrm state for encrypt is already set (the same one as decrypt)
    docker exec $local_node ip x p update src $local_host_ip/32 dst $remote_host_ip/32 \
            dir out priority 0 \
            mark $encrypt_mark mask 0xffffff00 \
            tmpl src $local_host_ip dst $remote_host_ip\
                    proto esp spi 0x00000003 reqid 1 mode tunnel

    # 5. capture ICMP on dst cilium_vxlan
    docker exec $remote_node tcpdump -w cilium_vxlan.pcap -c1 -ni cilium_vxlan "icmp and src host $local_pod_ip and dst host $remote_pod_ip" &
    sleep 1

    # 6. ping. Don't wait, no response is expected.
    old_encrypted_packets=$(docker exec $local_node ip -s x s get src $local_host_ip dst $remote_host_ip proto esp spi 3 mark $encrypt_mark mask 0xffffff00 | grep -Po '\d+(?=\(packets\))')
    docker exec $local_node ping -c 1 -W 0.1 $remote_pod_ip || true
    new_encrypted_packets=$(docker exec $local_node ip -s x s get src $local_host_ip dst $remote_host_ip proto esp spi 3 mark $encrypt_mark mask 0xffffff00 | grep -Po '\d+(?=\(packets\))')

    # 7. check ICMP is encrypted and captured
    (( old_encrypted_packets+1 == new_encrypted_packets ))
    sleep 1
    docker exec $remote_node tcpdump -r cilium_vxlan.pcap | grep -q 'ICMP echo'

    # 8. cleanup
    docker exec $local_node ip l d vxlan0
    docker exec $local_node iptables -t mangle -D OUTPUT -p udp --dport 8472 -j MARK --set-mark $encrypt_mark
    docker exec $local_node ip x p d src $local_host_ip/32 dst $remote_host_ip/32 \
            dir out \
            mark $encrypt_mark mask 0xffffff00
    docker exec $local_node ip l s cilium_vxlan up
}

test_vxlan_in_esp kind-worker kind-worker2
test_vxlan_in_esp kind-worker2 kind-worker

echo -e "\e[32mPASS\e[0m"
