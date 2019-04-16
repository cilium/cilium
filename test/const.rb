
$BUILD_NUMBER = ENV['BUILD_NUMBER'] || "0"
$JOB_NAME = ENV['JOB_BASE_NAME'] || "LOCAL"
$K8S_VERSION = ENV['K8S_VERSION'] || "1.14"
$K8S_NODES = (ENV['K8S_NODES'] || "2").to_i
$NFS = ENV['NFS']=="1"? true : false
$SERVER_BOX = (ENV['SERVER_BOX'] || "cilium/ubuntu-dev")
$SERVER_VERSION= "144"
$NETNEXT_SERVER_BOX= "cilium/ubuntu-next"
$NETNEXT_SERVER_VERSION= "21"
$IPv6=(ENV['IPv6'] || "0")
$CONTAINER_RUNTIME=(ENV['CONTAINER_RUNTIME'] || "docker")
$CNI_INTEGRATION=(ENV['CNI_INTEGRATION'] || "")

$MEMORY = (ENV['MEMORY'] || "4096").to_i
$CPU = (ENV['CPUS'] || "2").to_i

if ENV['NETNEXT'] == "true"
    $SERVER_BOX = $NETNEXT_SERVER_BOX
    $SERVER_VERSION = $NETNEXT_SERVER_VERSION
end

if __FILE__ == $0
    # Just print the correct format to donwnload the image if it's used in
    # Jenkins
    puts "#{$SERVER_BOX} --box-version #{$SERVER_VERSION}"
end
