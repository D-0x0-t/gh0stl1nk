import time
from scapy.all import RadioTap, Dot11, Dot11Action, Dot11QoS, LLC, SNAP, Raw, sendp

def current_timestamp():
    return int((time.time() - bootime) * 1000000)

# Action frame, category 4
def pkt_action(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=13, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Dot11Action(category=4)/Raw(load=payload) # check how to encover frame to not appear as "malformed" in wireshark (prob adding Raw(load=b"\x00"+payload))
    pkt.timestamp = current_timestamp()
    return pkt

# Action frame no ACK, NACK, category 127
def pkt_action_noack(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=14, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Dot11Action(category=127)/Raw(load=payload)
    pkt.timestamp = current_timestamp()
    return pkt

# QoS Data frame, added LLC/SNAP
def pkt_qos(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=2, subtype=8, addr1=BCAST, addr2=src, addr3=BCAST) # addr3 should be a BSSID
    pkt = RadioTap()/dot11/Dot11QoS()/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0x000000, code=0x0888)/Raw(load=payload)
    pkt.timestamp = current_timestamp()
    return pkt

# Data frame + LLC, SNAP
def pkt_data(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=2, subtype=0, addr1=BCAST, addr2=src, addr3=BCAST) # addr3 should be a BSSID
    pkt = RadioTap()/dot11/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0x000000, code=0x0888)/Raw(load=payload)
    pkt.timestamp = current_timestamp()
    return pkt

# 
def pkt_timing(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=6, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Raw(load=payload)
    pkt.timestamp = current_timestamp()
    return pkt

#
def pkt_atim(src, payload, BCAST="ff:ff:ff:ff:ff:ff"):
    dot11 = Dot11(type=0, subtype=9, addr1=BCAST, addr2=src, addr3=BCAST)
    pkt = RadioTap()/dot11/Raw(load=payload)
    pkt.timestamp = current_timestamp()
    return pkt
    
