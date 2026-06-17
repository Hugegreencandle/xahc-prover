"""`python -m watch <manifest> [--replay <fixture> | --ws <url>] [--account r...]`"""
import sys

from watch.watch import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
