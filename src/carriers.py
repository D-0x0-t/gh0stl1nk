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
    pkt = RadioTap()/dot11/Dot11Action(category=4)/Raw(load=payload)
    pkt.timestamp = tstamp
    return pkt

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