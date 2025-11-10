<div align="center">
    <img src="https://i.imgur.com/OyDsVBm.png" alt="gh0stlink logo" />
    <h3>A CCoWiFi<sup>1</sup> based on 802.11<sup>2</sup> frames.</h3>
    <h5>Also, a new way of sending cat pictures to your friends!</h5>
</div>

-----

## 1.- Overview

Gh0stl1nk is a covert channel based on 802.11 frames crafted with Scapy, developed as a proof of concept for secure and stealthy data exchange.

## 2.- Features
- **802.11 frame manipulation**: create and inject forged 802.11 frames (Timing, ATIM, Action, Data & QoS) using Scapy.
- **Data encryption**: messages are protected with AES-GCM + AAD bound to the MAC address, ensuring confidentiality and integrity.
- **File fragmentation & reassembly**: files are split into labeled fragments, each of which is encrypted and transmitted. The receiver reassembles them in order and reconstructs the file.
- **Reliability thanks to ACKs**: checksum-based ACKs to ensure proper transmissions.
- **Room membership**: each room has its own heartbeat, announcements and pruning of old clients.
- **Smart-MAC**: cover the source MAC address by scanning the air and spoofing a real AP.

## 3.- Requirements

### 3.1.- Python requirements
```python
scapy==2.6.1
pycryptodome>=3.11.0
netifaces>=0.11.0
psutil>=5.9.0
```

### 3.2.- System requirements

Gh0stl1nk is designed to run under GNU/Linux with **root** privileges.

It's also **necessary** to have a network adapter that supports monitor mode and frame injection.
Testing has been done with:
- [x] Alfa AWUS036ACS
- [x] TP-Link TL-WN722N v2
- [x] TP-Link Archer T3U Plus AC1300
- [x] BrosTrend AC5 650 Mbps
- [x] BrosTrend Long Range WiFi Adapter 1200 Mbps

*Remember to have the correct drivers for your adapter!*

## 4.- Usage

### 4.1.- Ensure you have an interface in monitor mode
```bash
$ sudo airmon-ng start wlanX
$ sudo python3 iflist.py
╒═════════════╤═══════╤═══════════╤══════════╤══════════════════════╤════════════╕
│ Interface   │ Phy   │ Driver    │ Status   │ Capabilities         │ USB port   │
╞═════════════╪═══════╪═══════════╪══════════╪══════════════════════╪════════════╡
│ wlan1       │ phy7  │ rtl8821au │ Monitor  │ monitor, managed, AP │ 001        │
├─────────────┼───────┼───────────┼──────────┼──────────────────────┼────────────┤
│ wlan2       │ phy6  │ rtl8821au │ Monitor  │ monitor, managed, AP │ 001        │
├─────────────┼───────┼───────────┼──────────┼──────────────────────┼────────────┤
│ wlan0       │ phy0  │ brcmfmac  │ Managed  │ monitor, managed, AP │ Internal   │
╘═════════════╧═══════╧═══════════╧══════════╧══════════════════════╧════════════╛
```

### 4.2.- Start gh0stl1nk
```bash
$ sudo python3 gh0stl1nk.py --help
usage: gh0stl1nk [-h] [-b] [-m PERSISTENT_MAC] [-r ROOM] [-s] [-u USERNAME] [--verbose] interface

the covert channel you didnt know you needed

positional arguments:
  interface                 interface to be used

options:
  -h, --help                show this help message and exit
  -b, --bannerless          disable welcome banner
  -m, --mac PERSISTENT_MAC  establish a custom MAC address
  -r, --room ROOM           directly connect to a room
  -s, --smart-mac           cover your MAC address based on the environment
  -u, --username USERNAME   your name inside gh0stl1nk
  --verbose                 set verbosity to True

$ sudo python3 gh0stl1nk.py wlan1 --room room_name --username D-0x0-t --bannerless
message>
```

## 5.- Contributing
Gh0stl1nk is open-source and contributions are welcome, any idea, bug, documentation improvement or whatever you can imagine that can keep the project evolving!

## 6.- Acronyms

- (1) **CCoWiFi**: Stands for Covert Channel over Wi-Fi.
- (2) **802.11**: IEEE standard for wireless LANs.