# -*- mode: ruby -*-
# vi: set ft=ruby :

# The source of truth for vagrant box versions.
# Sets SERVER_BOX, SERVER_VERSION, NETNEXT_SERVER_BOX and NETNEXT_SERVER_VERSION
# Accepts overrides from env variables
require_relative 'vagrant_box_defaults.rb'
$SERVER_BOX = (ENV['SERVER_BOX'] || $SERVER_BOX)
$SERVER_VERSION= (ENV['SERVER_VERSION'] || $SERVER_VERSION)
$NETNEXT_SERVER_BOX = (ENV['NETNEXT_SERVER_BOX'] || $NETNEXT_SERVER_BOX)
$NETNEXT_SERVER_VERSION= (ENV['NETNEXT_SERVER_VERSION'] || $NETNEXT_SERVER_VERSION)
$NO_BUILD = (ENV['NO_BUILD'] || "0")

if ENV['NETNEXT'] == "true" || ENV['NETNEXT'] == "1" then
    $SERVER_BOX = $NETNEXT_SERVER_BOX
    $SERVER_VERSION = $NETNEXT_SERVER_VERSION
    $vm_kernel = '+'
end

Vagrant.require_version ">= 2.0.0"

if ARGV.first == "up" && ENV['CILIUM_SCRIPT'] != 'true'
    raise Vagrant::Errors::VagrantError.new, <<END
Calling 'vagrant up' directly is not supported.  Instead, please run the
following to deploy a single-node cluster:
$ ./contrib/vagrant/start.sh

See the development guide for available configuration options:
https://docs.cilium.io/en/latest/contributing/development/dev_setup
END
end

if ENV['IPV4'] == '0'
    raise Vagrant::Errors::VagrantError.new, <<END
Disabling IPv4 is currently not allowed until k8s 1.9 is released
END
end

# Workaround issue as described here:
# https://github.com/cilium/cilium/pull/12520
class VagrantPlugins::ProviderVirtualBox::Action::Network
  def dhcp_server_matches_config?(dhcp_server, config)
    true
  end
end

$cleanup = <<SCRIPT
i=1
while [ "$i" -le "$((num_workers+1))" ]; do
    VBoxManage natnetwork add --netname natnet$i --network 192.168.0.0/16 --ipv6 on --enable
    i=$((i+1))
done 2>/dev/null

res=0
while [ "$res" == "0" ]; do
    VBoxManage natnetwork remove --netname natnet$i
    res=$?
    i=$((i+1))
done 2>/dev/null
SCRIPT

$bootstrap = <<SCRIPT
set -o errexit
set -o nounset
set -o pipefail

if [ -x /home/vagrant/go/src/github.com/cilium/cilium/.devvmrc ] ; then
   echo "----------------------------------------------------------------"
   echo "Executing .devvmrc"
   /home/vagrant/go/src/github.com/cilium/cilium/.devvmrc || true
fi

echo "----------------------------------------------------------------"
export PATH=/home/vagrant/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

echo "editing journald configuration"
bash -c "echo RateLimitIntervalSec=1s >> /etc/systemd/journald.conf"
bash -c "echo RateLimitBurst=10000 >> /etc/systemd/journald.conf"
echo "restarting systemd-journald"
systemctl restart systemd-journald
echo "getting status of systemd-journald"
service systemd-journald status
echo "done configuring journald"

service docker restart
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
echo 'export GOPATH=$(go env GOPATH)' >> /home/vagrant/.bashrc
chown -R vagrant:vagrant /home/vagrant 2>/dev/null || true
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map
chmod +x bpf-map
mv bpf-map /usr/bin
SCRIPT

$makeclean = ENV['MAKECLEAN'] ? "export MAKECLEAN=1" : ""
$build = <<SCRIPT
set -o errexit
set -o nounset
set -o pipefail

export PATH=/home/vagrant/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
#{$makeclean}
~/go/src/github.com/cilium/cilium/contrib/vagrant/build.sh
rm -fr ~/go/bin/cilium*
SCRIPT

$install = <<SCRIPT
set -o errexit
set -o nounset
set -o pipefail

# Add an exception for the cilium repo for the root user to fix the
# "fatal: unsafe repository ('/home/vagrant/go/src/github.com/cilium/cilium' is owned by someone else)"
# error condition when running `sudo make install`
git config --global --add safe.directory /home/vagrant/go/src/github.com/cilium/cilium

sudo -E make -C /home/vagrant/go/src/github.com/cilium/cilium/ install

sudo mkdir -p /etc/sysconfig
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-consul.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-docker.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-etcd.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-operator.service /lib/systemd/system
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium /etc/sysconfig

getent group cilium >/dev/null || sudo groupadd -r cilium
sudo usermod -a -G cilium vagrant
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

# Set locate to en_US.UTF-8
ENV["LC_ALL"] = "en_US.UTF-8"
ENV["LC_CTYPE"] = "en_US.UTF-8"

if ENV['CILIUM_SCRIPT'] != 'true' then
    Vagrant.configure(2) do |config|
        config.vm.define "runtime1"
        config.vm.define "k8s1"
        config.vm.define "k8s2"
        config.vm.define "k8s1+"
        config.vm.define "k8s2+"
    end
end

Vagrant.configure(2) do |config|
    config.trigger.before :up, :provision, :reload do |trigger|
        trigger.run = {inline: "bash -c '#{$cleanup}'"}
    end

    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    if $NO_BUILD == "0" then
        config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    end
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install
    config.vm.box_check_update = false

    config.vm.provider "virtualbox" do |vb|
        # Do not inherit DNS server from host, use proxy
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]

        # Prevent VirtualBox from interfering with host audio stack
        vb.customize ["modifyvm", :id, "--audio", "none"]

        # Enable HPET, the Go scheduler heavily relies on accurate timers.
        vb.customize ["modifyvm", :id, "--hpet", "on"]

        config.vm.box = $SERVER_BOX
        config.vm.box_version = $SERVER_VERSION
        vb.memory = ENV['VM_MEMORY'].to_i
        vb.cpus = ENV['VM_CPUS'].to_i
    end

    master_vm_name = "#{$vm_base_name}1#{$build_id_name}#{$vm_kernel}"
    config.vm.define master_vm_name, primary: true do |cm|
        node_ip = "#{$master_ip}"
        node_ipv6 = "#{$master_ipv6}"
        cm.vm.network "forwarded_port", guest: 6443, host: 7443, auto_correct: true
        cm.vm.network "forwarded_port", guest: 9081, host: 9081, auto_correct: true
        # 2345 is the default delv server port
        cm.vm.network "forwarded_port", guest: 2345, host: 2345, auto_correct: true
        cm.vm.network "private_network", ip: "#{$master_ip}",
            virtualbox__intnet: "cilium-test-#{$build_id}"
        if ENV['FIRST_IP_SUFFIX_NFS'] then
            $nfs_ipv4_master_addr = $node_nfs_base_ip + "#{ENV['FIRST_IP_SUFFIX_NFS']}"
        end
        cm.vm.network "private_network", ip: "#{$nfs_ipv4_master_addr}", bridge: "enp0s9"
        # Add IPv6 address this way or we get hit by a virtualbox bug
        cm.vm.provision "ipv6-config",
            type: "shell",
            run: "always",
            inline: "ip -6 a a #{$master_ipv6}/16 dev enp0s9"
        if ENV["IPV6_EXT"] then
            node_ip = "#{$master_ipv6}"
        end

        # Interface for the IPv6 NAT Service. The IP address doesn't matter as
        # it won't be used. We use an IPv4 address as newer versions of VBox
        # reject all IPv6 addresses.
        cm.vm.network "private_network",
            ip: "192.168.59.15"
        cm.vm.provider "virtualbox" do |vb|
            vb.customize ["modifyvm", :id, "--nic4", "natnetwork"]
            vb.customize ["modifyvm", :id, "--nat-network4", "natnet1"]
        end
        cm.vm.provision "ipv6-nat-config",
            type: "shell",
            run: "always",
            inline: "ip -6 r a default via fd17:625c:f037:2::1 dev enp0s10 || true"

        cm.vm.hostname = "#{$vm_base_name}1"
        if ENV['CILIUM_TEMP'] then
           if ENV["K8S"] then
               k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
               cm.vm.provision "k8s-install-master-part-1",
                   type: "shell",
                   run: "always",
                   env: {"node_ip" => node_ip, "node_ipv6" => node_ipv6},
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
                   env: {"node_ip" => node_ip, "node_ipv6" => node_ipv6},
                   privileged: true,
                   path: k8sinstall
           end
        end
    end

    $num_workers.times do |n|
        # n starts with 0
        node_vm_name = "#{$vm_base_name}#{n+2}#{$build_id_name}#{$vm_kernel}"
        node_hostname = "#{$vm_base_name}#{n+2}"
        config.vm.define node_vm_name do |node|
            node_ip = $workers_ipv4_addrs[n]
            node_ipv6 = $workers_ipv6_addrs[n]
            node.vm.network "private_network", ip: "#{node_ip}",
                virtualbox__intnet: "cilium-test-#{$build_id}"
            nfs_ipv4_addr = $workers_ipv4_addrs_nfs[n]
            node.vm.network "private_network", ip: "#{nfs_ipv4_addr}", bridge: "enp0s9"
            # Add IPv6 address this way or we get hit by a virtualbox bug
            node.vm.provision "ipv6-config",
                type: "shell",
                run: "always",
                inline: "ip -6 a a #{node_ipv6}/16 dev enp0s9"

            # Interface for the IPv6 NAT Service. The IP address doesn't matter
            # as it won't be used. We use an IPv4 address as newer versions of
            # VBox reject all IPv6 addresses.
            node.vm.network "private_network",
                ip: "192.168.59.15"
            node.vm.provider "virtualbox" do |vb|
                vb.customize ["modifyvm", :id, "--nic4", "natnetwork"]
                vb.customize ["modifyvm", :id, "--nat-network4", "natnet#{n+2}"]
            end
            node.vm.provision "ipv6-nat-config",
                type: "shell",
                run: "always",
                inline: "ip -6 r a default via fd17:625c:f037:2::1 dev enp0s10 || true"

            if ENV["IPV6_EXT"] then
                node_ip = "#{node_ipv6}"
            end
            node.vm.hostname = "#{node_hostname}"
            if ENV['CILIUM_TEMP'] then
                if ENV["K8S"] then
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
                    node.vm.provision "k8s-install-node-part-1",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip, "node_ipv6" => node_ipv6},
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
                        env: {"node_ip" => node_ip, "node_ipv6" => node_ipv6},
                        privileged: true,
                        path: k8sinstall
                end
            end
        end
    end
    cilium_dir = '.'
    cilium_path = '/home/vagrant/go/src/github.com/cilium/cilium'
    if ENV["SHARE_PARENT"] == "2" then
      cilium_dir = '../..'
      cilium_path = '/home/vagrant/go/src/github.com'
    elsif ENV["SHARE_PARENT"] then
      cilium_dir = '..'
      cilium_path = '/home/vagrant/go/src/github.com/cilium'
    end
    config.vm.synced_folder cilium_dir, cilium_path, type: "nfs", nfs_udp: false
    # Don't forget to enable this ports on your host before starting the VM
    # in order to have nfs working
    # iptables -I INPUT -s 192.168.61.0/24 -j ACCEPT"
    # if using nftables, in Fedora (with firewalld), use:
    # nft -f ./contrib/vagrant/nftables.rules

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
            config.vm.synced_folder "#{user_mount_from}", "#{user_mount_to}", type: "nfs", nfs_udp: false
        end
    end
end
