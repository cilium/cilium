import argparse

parser = argparse.ArgumentParser()
parser.add_argument('ghcomment', type=str) # used for `/test` trigger phrases
parser.add_argument('--focus', type=str, default="")
parser.add_argument('--kernel_version', type=str, default="")
parser.add_argument('--k8s_version', type=str, default="")
parser.add_argument('--retrieve', type=str, default="focus")

args = parser.parse_args()

# Update kernel_version to expected format
args.kernel_version = args.kernel_version.replace('.', '')
if args.kernel_version == "netnext":
	args.kernel_version = "net-next"

print(args.__dict__[args.retrieve])
