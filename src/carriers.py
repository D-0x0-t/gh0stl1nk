import time
from scapy.all import RadioTap, Dot11, Dot11Action, Dot11QoS, LLC, SNAP, Raw, sendp

# https://en.wikipedia.org/wiki/802.11_frame_types

# Timing Adevertise
def build_timing(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=6, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Raw(load=payload)
    pkt.timestamp = tstamp
    return pkt

# ATIM
def build_atim(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=9, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Raw(load=payload)
    pkt.timestamp = tstamp
    return pkt

# Action frame, category 4
def build_action(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=13, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Dot11Action(category=4)/Raw(load=payload) # check how to encover frame to not appear as "malformed" in wireshark (prob adding Raw(load=b"\x00"+payload))
    pkt.timestamp = tstamp
    return pkt

# Action frame no ACK, NACK, category 127
# Removed Action NACK due to incompatibilities in RX
# def build_action_noack(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
#     dot11 = Dot11(type=0, subtype=14, addr1=BCAST, addr2=src, addr3=BCAST)
#     pkt = RadioTap()/dot11/Dot11Action(category=127)/Raw(load=payload)
#     pkt.timestamp = tstamp
#     return pkt

# QoS Data frame, added LLC/SNAP
def build_qos(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=2, subtype=8, addr1=BCAST, addr2=src, addr3=BCAST) # addr3 should be a BSSID
    pkt = RadioTap()/dot11/Dot11QoS()/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0x000000, code=0x0888)/Raw(load=payload)
    pkt.timestamp = tstamp
    return pkt

# Data frame + LLC, SNAP
def build_data(src, payload, tstamp, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=2, subtype=0, addr1=BCAST, addr2=src, addr3=BCAST) # addr3 should be a BSSID
    pkt = RadioTap()/dot11/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0x000000, code=0x0888)/Raw(load=payload)
    pkt.timestamp = tstamp
    return pkt