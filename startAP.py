# This example is a simple 'hello world' for scapy-fakeap.
# An open network will be created that can be joined by 802.11 enabled devices.

import sys
from fakeap import *

name = sys.argv[2]
interface = sys.argv[1]
ap = FakeAccessPoint(interface, name)
ap.run()
