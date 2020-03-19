import argparse

parser = argparse.ArgumentParser()
parser.add_argument('placholder', type=str) # this is for test-me-please phrases
parser.add_argument('--focus', type=str, default="")
parser.add_argument('--version', type=str, default="")
parser.add_argument('--retrieve', type=str, default="focus")

args = parser.parse_args()

print args.__dict__[args.retrieve]
