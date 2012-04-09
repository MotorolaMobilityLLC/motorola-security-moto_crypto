#!/usr/bin/python
# This script calculates the HMAC-SHA256 of one file and writes the result
# to stdout

import binascii
import hashlib
import hmac
import sys

# Create the right content "hmac_sha256=yyy", yyy is the hmac sha256 value
# worked out by python hashlib from the file argv[1]
params = "hmac_sha256=" + hmac.new(binascii.unhexlify(sys.argv[1]), sys.stdin.read(), hashlib.sha256).hexdigest() + " fips=1";

sys.stdout.write(params)
