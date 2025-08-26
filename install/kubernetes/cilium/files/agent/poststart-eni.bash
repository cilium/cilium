set -o errexit
set -o pipefail
set -o nounset

# When running in AWS ENI mode, it's likely that 'aws-node' has
# had a chance to install SNAT iptables rules. These can result
# in dropped traffic, so we should attempt to remove them.
# We do it using a 'postStart' hook since this may need to run
# for nodes which might have already been init'ed but may still
# have dangling rules. This is safe because there are no
# dependencies on anything that is part of the startup script
# itself, and can be safely run multiple times per node (e.g. in
# case of a restart).
if [[ "$(iptables-save | grep -E -c 'AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN')" != "0" ]];
then
    echo 'Deleting iptables rules created by the AWS CNI VPC plugin'
    iptables-save | grep -E -v 'AWS-SNAT-CHAIN|AWS-CONNMARK-CHAIN' | iptables-restore
fi
echo 'Done!'
