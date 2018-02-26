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
echo "----------------------------------------------------------------"
export PATH=/home/vagrant/go/bin:/usr/local/clang/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
sudo service docker restart
echo 'cd ~/go/src/github.com/cilium/cilium' >> /home/vagrant/.bashrc
sudo -E /usr/local/go/bin/go get github.com/cilium/go-bindata/...
sudo -E /usr/local/go/bin/go get -u github.com/google/gops
sudo chown -R vagrant:vagrant /home/vagrant
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
sudo cp /home/vagrant/go/src/github.com/cilium/cilium/contrib/systemd/cilium /etc/sysconfig

sudo usermod -a -G cilium vagrant
SCRIPT

$testsuite = <<SCRIPT
make -C ~/go/src/github.com/cilium/cilium/ tests || exit 1
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

Vagrant.configure(2) do |config|
    config.vm.provision "bootstrap", type: "shell", inline: $bootstrap
    config.vm.provision "build", type: "shell", run: "always", privileged: false, inline: $build
    config.vm.provision "install", type: "shell", run: "always", privileged: false, inline: $install

    config.vm.provider "virtualbox" do |vb|
        # Do not inherit DNS server from host, use proxy
        vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
        vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
        config.vm.box = "cilium/ubuntu"
        config.vm.box_version = "32"
        vb.memory = ENV['VM_MEMORY'].to_i
        vb.cpus = ENV['VM_CPUS'].to_i

        config.vm.synced_folder '.', '/home/vagrant/go/src/github.com/cilium/cilium'
    end

    master_vm_name = "#{$vm_base_name}1#{$build_id_name}"
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
