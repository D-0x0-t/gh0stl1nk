#!/usr/bin/python3

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

import subprocess
import re
from tabulate import tabulate
import os

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return ""

def get_interfaces():
    iw_output = run_cmd(['iw', 'dev'])
    return re.findall(r'Interface\s+(\w+)', iw_output)

def get_driver(interface):
    out = run_cmd(['ethtool', '-i', interface])
    match = re.search(r'driver:\s+(\S+)', out)
    return match.group(1) if match else "-"

def get_mode(interface):
    out = run_cmd(['iwconfig', interface])
    match = re.search(r'Mode:(\w+)', out)
    return match.group(1) if match else "-"

def get_phy_for_interface(interface):
    path = f"/sys/class/net/{interface}/phy80211"
    if os.path.islink(path):
        target = os.readlink(path)
        return target.strip().split('/')[-1]  # Devuelve phyX
    return None

def get_capabilities(phy):
    if not phy:
        return "-"

    out = run_cmd(['iw', 'phy', phy, 'info'])
    caps = []
    if " * monitor" in out:
        caps.append("monitor")
    if " * managed" in out:
        caps.append("managed")
    if " * AP" in out:
        caps.append("AP")
    return ", ".join(caps) if caps else "-"

def get_usb_port(interface):
    driver = get_driver(interface)
    lsusb_tree = run_cmd(['lsusb', '-t'])
    lines = lsusb_tree.splitlines()

    for line in lines:
        if f"Driver={driver}" in line:
            match = re.search(r'Port\s+(\d+):', line)
            if match:
                return match.group(1)
    return "Internal"

def analizar_antenas():
    interfaces = get_interfaces()
    datos = []

    for iface in interfaces:
        phy = get_phy_for_interface(iface)
        driver = get_driver(iface)
        modo = get_mode(iface)
        capacidades = get_capabilities(phy)
        puerto_usb = get_usb_port(iface)

        datos.append({
            "Interface": iface,
            "Phy": phy if phy else "-",
            "Driver": driver,
            "Status": modo,
            "Capabilities": capacidades,
            "USB port": puerto_usb
        })

    return datos

def imprimir_tabla(data):
    print(tabulate(data, headers="keys", tablefmt="fancy_grid"))

if __name__ == "__main__":
    resultados = analizar_antenas()
    imprimir_tabla(resultados)
