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
import sys, os, re, subprocess
from time import sleep
from pwn import log

timer = 0.5

def iface_exists(iface: str) -> bool:
	return os.path.exists(f"/sys/class/net/{iface}")

def _run(cmd: str, timeout: float = 4.0) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout if p.stdout is not None else ""
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "" if hasattr(e, "stderr") else "")
        return 124, out
    except Exception as e:
        return 125, f"_run exception: {e}"

def iface_to_phy(iface: str) -> str | None:
    rc, out = _run(f"iw dev {iface} info")
    m = re.search(r"\bwiphy\s+(\d+)", out)
    return f"phy{m.group(1)}" if m else None
    return None

def phy_allows_vifs(phy: str) -> bool:
	rc, out = _run(f"iw phy {phy} info")
	if "interface combinations are not supported" in out:
		return False
	return True


try:
	iface = str(sys.argv[1]).lower()
	if iface.lower() == "kill" or iface.lower() == "del":
		iface = str(sys.argv[2])
		mon_iface_name = "mon" + iface[-1:]
		if not phy_allows_vifs(iface_to_phy(iface)):
			natural_iface_name = "wlan" + iface[-1:]
			p = log.progress(f"Restablishing {mon_iface_name} into {natural_iface_name}")
			rc, out = _run(f"ip link set {mon_iface_name} down", timeout=3.0)
			rc, out = _run(f"iw dev {mon_iface_name} set type managed", timeout=3.0)
			rc, out = _run(f"ip link set {mon_iface_name} up", timeout=3.0)
			rc, out = _run(f"ip link set {mon_iface_name} name {natural_iface_name}", timeout=3.0)
			p.success("Done")
		else:	
			p = log.progress(f"Killing VIF {mon_iface_name}")
			cmd1 = f"ip link set {mon_iface_name} down"
			cmd2 = f"iw dev {mon_iface_name} del"
			rc, out = _run(cmd1)
			sleep(timer)
			rc, out = _run(cmd2)
			sleep(timer)
			p.success("Done")
	else:
		mon_iface_name = "mon" + iface[-1:]
		if iface_exists(iface):
			# Check if driver/phy allows virtualization of interfaces
			if not phy_allows_vifs(iface_to_phy(iface)):
				p = log.progress(f"Establishing {iface} in monitor mode and changing name to {mon_iface_name}")
				rc, out = _run(f"ip link set {iface} down", timeout=3.0)
				rc, out = _run(f"iw dev {iface} set type monitor", timeout=3.0)
				if rc != 0:
					print(f"[!] Error setting {iface} in monitor mode.")
					rc, out = _run(f"iw dev {iface} set type managed", timeout=3.0)
					rc, out = _run(f"ip link set {iface} up")
					sys.exit(1)
				rc, out = _run(f"ip link set {iface} up", timeout=3.0)
				rc, out = _run(f"ip link set {iface} name {mon_iface_name}", timeout=3.0)
				p.success("Done")
			else:
				p = log.progress(f"Initializing VIF in monitor mode for {iface} ({mon_iface_name})")
				cmd1 = f"iw dev {iface} interface add {mon_iface_name} type monitor"
				cmd2 = f"ip link set {mon_iface_name} up"
				rc, out = _run(cmd1)
				sleep(timer)
				rc, out = _run(cmd2)
				sleep(timer)
				p.success("Done")
		else:
			print(f"Interface {iface} isn't shown under /sys/class/net/.\nPlease try again or check your antennas.")
except Error as e:
	print(e)
	print(f"Usage: python3 {sys.argv[0]} [kill|del] <physical interface>")