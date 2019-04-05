# -*- mode: ruby -*-
# vi: set ft=ruby :

# The source of truth for vagrant box versions.
# Sets SERVER_BOX, SERVER_VERSION, NETNEXT_SERVER_BOXET and NEXT_SERVER_VERSION
# Accepts overrides from env variables
require_relative 'vagrant_box_defaults.rb'
$SERVER_BOX = (ENV['SERVER_BOX'] || $SERVER_BOX)
$SERVER_VERSION= (ENV['SERVER_VERSION'] || $SERVER_VERSION)

Vagrant.require_version ">= 2.0.0"

if ARGV.first == "up" && ENV['CILIUM_SCRIPT'] != 'true'
    raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the following:
  export NWORKERS=n
  ./contrib/vagrant/start.sh
END
end

if ENV['IPV4'] == '0'
    raise Vagrant::Errors::VagrantError.new, <<END
Disabling IPv4 is currently not allowed until k8s 1.9 is released
END
end

$bootstrap = <<SCRIPT
echo "----------------------------------------------------------------"
export PATH=/home/vagrant/go/bin:/usr/local/clang/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

echo "editing journald configuration"
sudo bash -c "echo RateLimitIntervalSec=1s >> /etc/systemd/journald.conf"
sudo bash -c "echo RateLimitBurst=10000 >> /etc/systemd/journald.conf"
echo "restarting systemd-journald"
sudo systemctl restart systemd-journald
echo "getting status of systemd-journald"
sudo service systemd-journald status
echo "done configuring journald"

sudo service docker restart
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
sudo -E /usr/local/go/bin/go get github.com/cilium/go-bindata/...
sudo -E /usr/local/go/bin/go get -u github.com/google/gops
sudo -E /usr/local/go/bin/go get -d github.com/lyft/protoc-gen-validate
sudo -E /usr/local/go/bin/go get -u github.com/gordonklaus/ineffassign
(cd ~/go/src/github.com/lyft/protoc-gen-validate ; sudo git checkout 4349a359d42fdfee53b85dd5c89a2f169e1dc6b2 ; make build)
sudo chown -R vagrant:vagrant /home/vagrant 2>/dev/null
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map
chmod +x bpf-map
mv bpf-map /usr/bin
SCRIPT

$build = <<SCRIPT
export PATH=/home/vagrant/go/bin:/usr/local/clang/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
~/go/src/github.com/cilium/cilium/common/build.sh
rm -fr ~/go/bin/cilium*
SCRIPT

$install = <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/cilium/cilium/ install

sudo mkdir -p /etc/sysconfig
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-consul.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-docker.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-etcd.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-operator.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium /etc/sysconfig

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite = <<SCRIPT
sudo -E env PATH="${PATH}" make -C ~/go/src/github.com/cilium/cilium/ runtime-tests
SCRIPT

$node_ip_base = ENV['IPV4_BASE_ADDR'] || ""
$node_nfs_base_ip = ENV['IPV4_BASE_ADDR_NFS'] || ""
$num_workers = (ENV['NWORKERS'] || 0).to_i
$workers_ipv4_addrs = $num_workers.times.collect { |n| $node_ip_base + "#{n+(ENV['FIRST_IP_SUFFIX']).to_i+1}" }
$workers_ipv4_addrs_nfs = $num_workers.times.collect { |n| $node_nfs_base_ip + "#{n+(ENV['FIRST_IP_SUFFIX_NFS']).to_i+1}" }
$master_ip = ENV['MASTER_IPV4']
$master_ipv6 = ENV['MASTER_IPV6_PUBLIC']
$workers_ipv6_addrs_str = ENV['IPV6_PUBLIC_WORKERS_ADDRS'] || ""
$workers_ipv6_addrs = $workers_ipv6_addrs_str.split(' ')

# Create unique ID for use in vboxnet name so Jenkins pipeline can have concurrent builds.
$job_name = ENV['JOB_BASE_NAME'] || "local"

$build_number = ENV['BUILD_NUMBER'] || "0"
$build_id = "#{$job_name}-#{$build_number}"

# Only create the build_id_name for Jenkins environment so that
# we can run VMs locally without having any the `build_id` in the name.
if ENV['BUILD_NUMBER'] then
    $build_id_name = "-build-#{$build_id}"
end

if ENV['K8S'] then
    $vm_base_name = "k8s"
else
    $vm_base_name = "runtime"
end

# We need this workaround since kube-proxy is not aware of multiple network
# interfaces. If we send a packet to a service IP that packet is sent
# to the default route, because the service IP is unknown by the linux routing
# table, with the source IP of the interface in the default routing table, even
# though the service IP should be routed to a different interface.
# This particular workaround is only needed for cilium, running on a pod on host
# network namespace, to reach out kube-api-server.
$kube_proxy_workaround = <<SCRIPT
sudo iptables -t nat -A POSTROUTING -o enp0s8 ! -s 192.168.34.12 -j MASQUERADE
SCRIPT

Vagrant.configure(2) do |config|
    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install

    config.vm.provider "virtualbox" do |vb|
        # Do not inherit DNS server from host, use proxy
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]

        config.vm.box = "cilium/ubuntu-dev"
        config.vm.box_version = $SERVER_VERSION
        vb.memory = ENV['VM_MEMORY'].to_i
        vb.cpus = ENV['VM_CPUS'].to_i
        if ENV["NFS"] then
            mount_type = "nfs"
            # Don't forget to enable this ports on your host before starting the VM
            # in order to have nfs working
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 111 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 2049 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 20048 -j ACCEPT
        else
            mount_type = ""
        end
        config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: mount_type
        if ENV['USER_MOUNTS'] then
            # Allow multiple mounts divided by commas
            ENV['USER_MOUNTS'].split(",").each do |mnt|
                # Split "<to>=<from>"
                user_mount = mnt.split("=", 2)
                # Only one element, assume a path relative to home directories in both ends
                if user_mount.length == 1 then
                    user_mount_to = "/home/vagrant/" + user_mount[0]
                    user_mount_from = "~/" + user_mount[0]
                else
                    user_mount_to = user_mount[0]
                    # Remove "~/" prefix if any.
                    if user_mount_to.start_with?('~/') then
                        user_mount_to[0..1] = ''
                    end
                    # Add home directory prefix for non-absolute paths
                    if !user_mount_to.start_with?('/') then
                        user_mount_to = "/home/vagrant/" + user_mount_to
                    end
                    user_mount_from = user_mount[1]
                    # Add home prefix for host for any path in the project directory
                    # as it is already mounted.
                    if !user_mount_from.start_with?('/', '.', '~') then
                        user_mount_from = "~/" + user_mount_from
                    end
                end
                puts "Mounting host directory #{user_mount_from} as #{user_mount_to}"
                config.vm.synced_folder "#{user_mount_from}", "#{user_mount_to}", type: mount_type
            end
        end
    end

    master_vm_name = "#{$vm_base_name}1#{$build_id_name}"
    config.vm.define master_vm_name, primary: true do |cm|
        node_ip = "#{$master_ip}"
		cm.vm.network "forwarded_port", guest: 6443, host: 7443
        cm.vm.network "private_network", ip: "#{$master_ip}",
            virtualbox__intnet: "cilium-test-#{$build_id}",
            :libvirt__guest_ipv6 => "yes",
            :libvirt__dhcp_enabled => false
        if ENV["NFS"] || ENV["IPV6_EXT"] then
            if ENV['FIRST_IP_SUFFIX_NFS'] then
                $nfs_ipv4_master_addr = $node_nfs_base_ip + "#{ENV['FIRST_IP_SUFFIX_NFS']}"
            end
            cm.vm.network "private_network", ip: "#{$nfs_ipv4_master_addr}", bridge: "enp0s9"
            # Add IPv6 address this way or we get hit by a virtualbox bug
            cm.vm.provision "ipv6-config",
                type: "shell",
                run: "always",
                inline: "ip -6 a a #{$master_ipv6}/16 dev enp0s9"
            node_ip = "#{$nfs_ipv4_master_addr}"
            if ENV["IPV6_EXT"] then
                node_ip = "#{$master_ipv6}"
            end
        end
        cm.vm.hostname = "#{$vm_base_name}1"
        if ENV['CILIUM_TEMP'] then
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
               cm.vm.provision "k8s-install-master-part-1",
                   type: "shell",
                   run: "always",
                   env: {"node_ip" => node_ip},
                   privileged: true,
                   path: k8sinstall
           end
           script = "#{ENV['CILIUM_TEMP']}/node-1.sh"
           cm.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
           # In k8s mode cilium needs etcd in order to run which was started in
           # the first part of the script. The 2nd part will install the
           # policies into kubernetes and cilium.
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
               cm.vm.provision "k8s-install-master-part-2",
                   type: "shell",
                   run: "always",
                   env: {"node_ip" => node_ip},
                   privileged: true,
                   path: k8sinstall
           end
        end
        if ENV['RUN_TEST_SUITE'] then
           cm.vm.provision "testsuite", run: "always", type: "shell", privileged: false, inline: $testsuite
        end
    end

    $num_workers.times do |n|
        # n starts with 0
        node_vm_name = "#{$vm_base_name}#{n+2}#{$build_id_name}"
        node_hostname = "#{$vm_base_name}#{n+2}"
        config.vm.define node_vm_name do |node|
            node_ip = $workers_ipv4_addrs[n]
            node.vm.network "private_network", ip: "#{node_ip}",
                virtualbox__intnet: "cilium-test-#{$build_id}",
                :libvirt__guest_ipv6 => 'yes',
                :libvirt__dhcp_enabled => false
            if ENV["NFS"] || ENV["IPV6_EXT"] then
                nfs_ipv4_addr = $workers_ipv4_addrs_nfs[n]
                node_ip = "#{nfs_ipv4_addr}"
                ipv6_addr = $workers_ipv6_addrs[n]
                node.vm.network "private_network", ip: "#{nfs_ipv4_addr}", bridge: "enp0s9"
                # Add IPv6 address this way or we get hit by a virtualbox bug
                node.vm.provision "ipv6-config",
                    type: "shell",
                    run: "always",
                    inline: "ip -6 a a #{ipv6_addr}/16 dev enp0s9"
                if ENV["IPV6_EXT"] then
                    node_ip = "#{ipv6_addr}"
                end
            end
            node.vm.hostname = "#{$vm_base_name}#{n+2}"
            if ENV['CILIUM_TEMP'] then
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
                    node.vm.provision "k8s-install-node-part-1",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip},
                        privileged: true,
                        path: k8sinstall
                end
                script = "#{ENV['CILIUM_TEMP']}/node-#{n+2}.sh"
                node.vm.provision "config-install", type: "shell", privileged: true, run: "always", path: script
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-2nd-part.sh"
                    node.vm.provision "k8s-install-node-part-2",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip},
                        privileged: true,
                        path: k8sinstall
                end
            end
        end
    end
end
