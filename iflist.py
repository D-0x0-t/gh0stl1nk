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
