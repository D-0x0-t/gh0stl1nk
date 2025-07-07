#!/usr/bin/python3
import sys, os
from time import sleep
from pwn import log

timer = 0.5

def iface_exists(iface: str) -> bool:
	return os.path.exists(f"/sys/class/net/{iface}")

try:
	iface = str(sys.argv[1]).lower()
	if iface.lower() == "kill" or iface.lower() == "del":
		iface = str(sys.argv[2])
		vif_name = "mon" + iface[-1:]
		p = log.progress(f"Killing VIF {vif_name}")
		cmd1 = f"ip link set {vif_name} down"
		cmd2 = f"iw dev {vif_name} del"
		os.system(cmd1)
		sleep(timer)
		os.system(cmd2)
		sleep(timer)
		p.success("Done")
	else:
		vif_name = "mon" + iface[-1:]
		if iface_exists(iface):
			p = log.progress(f"Initializing VIF in monitor mode for {iface} ({vif_name})")
			cmd1 = f"iw dev {iface} interface add {vif_name} type monitor"
			cmd2 = f"ip link set {vif_name} up"
			os.system(cmd1)
			sleep(timer)
			os.system(cmd2)
			sleep(timer)
			p.success("Done")
		else:
			print(f"Interface {iface} isn't shown under /sys/class/net/.\nPlease try again or check your antennas.")
except:
	print(f"Usage: python3 {sys.argv[0]} [kill] <physical interface>")
