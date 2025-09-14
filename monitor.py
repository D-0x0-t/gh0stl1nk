# BSD 3-Clause License
#
# Copyright (c) 2025, Diego (0xD0t).
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#!/usr/bin/python3
import sys, os
from time import sleep

timer = 0.5

def iface_exists(iface: str) -> bool:
	return os.path.exists(f"/sys/class/net/{iface}")

try:
	iface = str(sys.argv[1]).lower()
	if iface.lower() == "kill" or iface.lower() == "del":
		iface = str(sys.argv[2])
		vif_name = "mon" + iface[-1:]
		cmd1 = f"ip link set {vif_name} down"
		cmd2 = f"iw dev {vif_name} del"
		os.system(cmd1)
		sleep(timer)
		os.system(cmd2)
		sleep(timer)
	else:
		vif_name = "mon" + iface[-1:]
		if iface_exists(iface):
			cmd1 = f"iw dev {iface} interface add {vif_name} type monitor"
			cmd2 = f"ip link set {vif_name} up"
			os.system(cmd1)
			sleep(timer)
			os.system(cmd2)
			sleep(timer)
		else:
			print(f"Interface {iface} isn't shown under /sys/class/net/.\nPlease try again or check your antennas.")
except:
	print(f"Usage: python3 {sys.argv[0]} [kill] <physical interface>")
