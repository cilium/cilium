# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.8.3"

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

# start.sh sets BAZEL_VERSION before calling us.
BAZEL_VERSION = ENV['BAZEL_VERSION']

$bootstrap = <<SCRIPT
sudo service docker restart
sudo apt-get -y update || true
sudo apt-get -y install socat curl jq realpath pv tmux python-sphinx python-pip yamllint
sudo pip install --upgrade pip
sudo pip install sphinx sphinxcontrib-httpdomain sphinxcontrib-openapi
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
export GOPATH=/home/vagrant/go
sudo -E /usr/local/go/bin/go get github.com/jteeuwen/go-bindata/...
sudo -E /usr/local/go/bin/go get -u github.com/google/gops
chown -R vagrant:vagrant $GOPATH
curl -SsL https://github.com/cilium/bpf-map/releases/download/v1.0/bpf-map -o bpf-map
chmod +x bpf-map
mv bpf-map /usr/bin
if [[ $(command -v bazel) && "$(bazel version | grep 'label' | cut -d ' ' -f 3)" = #{BAZEL_VERSION} ]]; then
  echo "Bazel #{BAZEL_VERSION} already installed, skipping fetch."
else
  wget -nv https://github.com/bazelbuild/bazel/releases/download/#{BAZEL_VERSION}/bazel-#{BAZEL_VERSION}-installer-linux-x86_64.sh
  chmod +x bazel-#{BAZEL_VERSION}-installer-linux-x86_64.sh
  sudo -E ./bazel-#{BAZEL_VERSION}-installer-linux-x86_64.sh
  sudo -E mv /usr/local/bin/bazel /usr/bin
  rm bazel-#{BAZEL_VERSION}-installer-linux-x86_64.sh
fi
SCRIPT

$envoyexport = ENV['CILIUM_USE_ENVOY'] ? "export CILIUM_USE_ENVOY=1\n" : ""
$build = $envoyexport
$install = $envoyexport
$testsuite = $envoyexport

$build += <<SCRIPT
~/go/src/github.com/cilium/cilium/common/build.sh
rm -fr ~/go/bin/cilium*
SCRIPT

$install += <<SCRIPT
sudo -E make -C /home/vagrant/go/src/github.com/cilium/cilium/ install

if [ -n "$(grep DISTRIB_RELEASE=14.04 /etc/lsb-release)" ]; then
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-docker.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-consul.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-policy-watcher.conf /etc/init/
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/upstart/cilium-etcd.conf /etc/init/
    sudo rm -rf /var/log/upstart/cilium-*
else
    sudo mkdir -p /etc/sysconfig
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-consul.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-docker.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium-etcd.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium.service /lib/systemd/system
    sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium /etc/sysconfig
fi

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite += <<SCRIPT
make -C ~/go/src/github.com/cilium/cilium/ tests || exit 1
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
if ENV['CILIUM_USE_ENVOY'] then
    $build_id += "-envoy"
end

# Only create the build_id_name for Jenkins environment so that
# we can run VMs locally without having any the `build_id` in the name.
if ENV['BUILD_NUMBER'] then
    $build_id_name = "-build-#{$build_id}"
    $rsync_exclude = ".git"
else
    $rsync_exclude = "GIT_VERSION"
end

if ENV['K8S'] then
    $k8stag = ENV['K8STAG'] || "-k8s"
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

    config.vm.provider :libvirt do |libvirt|
        config.vm.box = "cilium/ubuntu-16.10"
        config.vm.box_version = "2.0"
        libvirt.memory = ENV['VM_MEMORY'].to_i
        libvirt.cpus = ENV['VM_CPUS'].to_i
        config.vm.synced_folder ".", "/home/vagrant/go/src/github.com/cilium/cilium", disabled: false
    end

    config.vm.provider "virtualbox" do |vb|
        # Do not inherit DNS server from host, use proxy
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]

        config.vm.box = "cilium/ubuntu-16.10"
	config.vm.box_version = "2.7"
        vb.memory = ENV['VM_MEMORY'].to_i
        vb.cpus = ENV['VM_CPUS'].to_i

        if ENV["NFS"] then
            config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "nfs"
            # Don't forget to enable this ports on your host before starting the VM
            # in order to have nfs working
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 111 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 2049 -j ACCEPT
            # iptables -I INPUT -p udp -s 192.168.34.0/24 --dport 20048 -j ACCEPT
        else
            # run rsync with options:
            #  --links: preserve symlinks
            #  --checksum: skip based on checksum, not mod-time & size (avoid unnecessary bazel rebuilds)
            #  --delete: delete extraneous files from dest dirs
            #  --force: force deletion of dirs even if not empty
            #  --delete-excluded: also delete excluded files from dest dirs
            #  --archive: archive mode; equals -rlptgoD (no -H,-A,-X)
            #  -z: compress file data during the transfer
            config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium', type: "rsync",
                rsync__exclude: [$rsync_exclude, "src"], rsync__args: ["--verbose", "--archive", "--delete", "--force", "--delete-excluded", "-z", "--links", "--checksum"]
        end
    end

    master_vm_name = "cilium#{$k8stag}-master#{$build_id_name}"
    config.vm.define master_vm_name, primary: true do |cm|
        node_ip = "#{$master_ip}"
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
        cm.vm.hostname = "cilium#{$k8stag}-master"
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
           script = "#{ENV['CILIUM_TEMP']}/"
           script += ENV['CILIUM_USE_ENVOY'] ? "cilium-master-envoy.sh" : "cilium-master.sh"
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
        node_vm_name = "cilium#{$k8stag}-node-#{n+2}#{$build_id_name}"
        node_hostname = "cilium#{$k8stag}-node-#{n+2}"
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
            node.vm.hostname = "cilium#{$k8stag}-node-#{n+2}"
            if ENV['CILIUM_TEMP'] then
                if ENV["K8S"] then
                    node.vm.provision "kube-proxy-workaround", type: "shell", run: "always", inline: $kube_proxy_workaround
                    k8sinstall = "#{ENV['CILIUM_TEMP']}/cilium-k8s-install-1st-part.sh"
                    node.vm.provision "k8s-install-node-part-1",
                        type: "shell",
                        run: "always",
                        env: {"node_ip" => node_ip},
                        privileged: true,
                        path: k8sinstall
                end
                script = "#{ENV['CILIUM_TEMP']}/node-start-#{n+2}.sh"
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
