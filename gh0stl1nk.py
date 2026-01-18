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


# Imports
import time
import base64
import logging
import argparse
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import os, sys, re, random
import threading, subprocess
from datetime import datetime
from hashlib import sha256
from tqdm import tqdm
from zlib import compress, decompress
from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from scapy.all import sniff, sendp, Raw, conf
from scapy.layers.dot11 import RadioTap, Dot11
from scapy.volatile import RandMAC

# Gh0stl1nk internals
from src.file_control import fragment_file, parse_decrypted
from src.rooms import RoomRegistry, VoteSession, active_votes
from src.rooms import quorum
from src.utils import *
from src.channel_hop import Channel
from src.carriers import *
from src.crypt_utils import checksum, kdf_from_room, gcm_encrypt, gcm_decrypt


# General Config
count = 10 # default number of times each packet is sent
maxpayload = 1024 # maximum payload size (based on MTU - pkt default size)
verbose = False # default verbosity
input_request_message = "message> " # user prompt

bootime = time.time()
recent_messages = set() # prevent loopback
recent_queue = deque() # prevent loopback
MAX_TRACKED = 100
ack_wait = {}
ack_lock = threading.Lock()
current_input = ""
HEARTBEAT_INTERVAL = 30 # timer for sending heartbeats to other room members

# File transfer config
file_sessions = {} # file sessions dict
tx_sessions_cache = {} # file sessions cache (for NACK)
FILE_ACK_HEADER_PREFIX = "[FILE-ACK]:" # file ACK header
FILE_NACK_HEADER_PREFIX = "[FILE-NACK]:" # file Negative ACK header
FILE_IDLE_TOUT = 5.0 # seconds without RX activity before requesting fragment retransmission
FILE_NACK_CD = 1.0 # min seconds between NACKs
FILE_NACK_BATCH = 50 # max fragment retransmission requests per NACK
FILE_RX_CLOSE = 120 # time to drop incomplete sessions
TX_SESSION_CACHE_TIMER = 120.0 # time to keep fragments cached without receiving file ACK
TX_IDX_MAX_RETRIES = 10 # max rertansmission attempts

# Argparse
def argument_parser():
    parser = argparse.ArgumentParser(prog="gh0stl1nk", description="the covert channel you didn't know you needed")
    parser.add_argument("interface", help="interface to be used")
    parser.add_argument("-b", "--bannerless", dest="bannerless", default=False, help="disable welcome banner", action="store_true")
    parser.add_argument("-m", "--mac", dest="persistent_mac", default=None, help="establish a custom MAC address")
    parser.add_argument("-r", "--room", dest="room", help="directly connect to a room")
    parser.add_argument("-s", "--smart-mac", dest="smart_mac", help="cover your MAC address based on the environment", action="store_true")
    parser.add_argument("-u", "--username", dest="username", help="your name inside gh0stl1nk")
    parser.add_argument("--verbose", dest="verbose", default=False, help="set verbosity to True", action="store_true")
    return parser.parse_args()   


# Local utilities
def send_heartbeat():
    global room_name, persistent_mac
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        heartbeat_control_msg = f"[USR-HB]||{room_name}||{persistent_mac}"
        send_plain(heartbeat_control_msg)
        if verbose:
            print(f"DEBUG: Sent heartbeat for room {room_name} and MAC {persistent_mac}")
        room = registry.rooms[room_name]
        room.add_member(persistent_mac)

def prune_loop():
    while True:
        for room in registry.rooms.values():
            room.prune_dead(timeout=90)
        time.sleep(5)

def vote_cleanup_loop():
    while True:
        for vid, vs in list(active_votes.items()):
            if vs.is_expired():
                del active_votes[vid]
        time.sleep(1)

def current_timestamp():
    return int((time.time() - bootime) * 1000000)

def chat_encrypt(message):
    pt = (username + "~" + message).encode()
    blob = gcm_encrypt(room_key, args.room, persistent_mac, pt)
    return blob

def decrypt_payload(data, source_mac):
    try:
        pt = gcm_decrypt(room_key, args.room, source_mac.lower(), data)
        if not pt:
            return None, None
        text = pt.decode(errors="ignore")
        if "~" in text:
            return text.strip().split("~", 1)
    except Exception:
        pass
    return None, None

def build_packet(encrypted_msg):
    global persistent_mac
    random_carrier = random.randint(0, 4)
    if random_carrier == 0:
        pkt = build_timing(persistent_mac, encrypted_msg, current_timestamp())
        if verbose:
            carrier_name = "Timing Advertise"
    elif random_carrier == 1:
        pkt = build_atim(persistent_mac, encrypted_msg, current_timestamp())
        if verbose:
            carrier_name = "ATIM"
    elif random_carrier == 2:
        pkt = build_action(persistent_mac, encrypted_msg, current_timestamp())
        if verbose:
            carrier_name = "Action frame (4)"
    elif random_carrier == 3:
        pkt = build_qos(persistent_mac, encrypted_msg, current_timestamp())
        if verbose:
            carrier_name = "QoS Data"
    elif random_carrier == 4:
        pkt = build_data(persistent_mac, encrypted_msg, current_timestamp())
        if verbose:
            carrier_name = "Data + LLC/SNAP"
    
    if verbose:
        print(f"Using {carrier_name}")    
    return pkt

# ACK untracked
def send_plain(msg):
    encrypted = chat_encrypt(msg)
    pkt = build_packet(encrypted)
    sendp(pkt, monitor=True, iface=iface, verbose=0, count=5, inter=0.01)

def announce_user(user, status):
    global room_name, persistent_mac
    if status == "join":
        encrypted_ann = chat_encrypt("[USR-ANN]:" + str(user) + f"||{room_name}||{persistent_mac}")  
    elif status == "left":
        encrypted_ann = chat_encrypt("[USR-LFT]:" + str(user)+ f"||{room_name}||{persistent_mac}")
    pkt = build_packet(encrypted_ann)
    sendp(pkt, monitor=True, iface=iface, verbose=0, count=10, inter=0.01)
    if verbose:
            print(f"DEBUG: Announced user with {encrypted_ann}")

def request_mac_swap(address, user):
    sendp(build_packet(chat_encrypt("[REQ-MAC]:" + str(address))), monitor=True, iface=iface, verbose=0, count=10, inter=0.01)
    if verbose:
        print(f"DEBUG: Requested {user} to change his MAC address ({address})")

def send_encrypted_msg(msg):

    # Empty messages
    if not msg.strip():
        return

    encrypted = chat_encrypt(msg)
    pkt = build_packet(encrypted)
    msg_hash  = checksum(encrypted)

    with ack_lock:
        ack_wait[msg_hash] = time.time()
    if verbose:
        print(f"[gh0stl1nk] awaiting ACK for {msg_hash}")

    for attempt in range(count):
        sendp(pkt, monitor=True, iface=iface, verbose=0, count=1, inter=0.01)
        sender_pretty_printer("You", current_input)
        if verbose:
            print(f"[gh0stl1nk] sent {msg_hash}, attempt {attempt+1}/{count}")

        if wait_for_ack(msg_hash, ack_wait, ack_lock, timeout=0.25):
            if verbose:
                print(f"[ACK] received for {msg_hash}")
            break
    else:
        print(f"[!] No ACK received for hash \"{msg_hash}\" after {count} attempts (messages sent)")

def handle_ack(msg):
    if msg.startswith("[RCV-ACK]"):
        ack_hash = msg.split(":", 1)[1].strip()
        with ack_lock:
            if ack_hash in ack_wait:
                if verbose:
                    print(f"[ACK] Received confirmation for {ack_hash}, {msg}")
                del ack_wait[ack_hash]

def handle_file_ack(msg):
    try:
        session_id = msg.split(FILE_ACK_HEADER_PREFIX, 1)[1].strip()
    except Exception:
        return
    
    if session_id in tx_sessions_cache:
        if verbose:
            print(f"ACK received for session {session_id}, clearing TX cache")
        del tx_sessions_cache[session_id]

def handle_file_nack(msg):
    try:
        payload = msg.split(FILE_NACK_HEADER_PREFIX, 1)[1].strip()
        session_id, missing_csv = payload.split("|", 1)
        session_id = session_id.strip()
        missing = [int(x) for x in missing_csv.split(",") if x.strip().isdigit()]
    except Exception:
        return
    
    sess = tx_sessions_cache.get(session_id)
    if not sess:
        return

    total = sess.get("total")
    for idx in missing:
        retries = sess["retries"].get(idx, 0)
        if retries >= TX_IDX_MAX_RETRIES:
            continue
        frag = sess["fragments"].get(idx)
        if not frag:
            continue
        
        pkt = build_packet(frag)
        sendp(pkt, monitor=True, iface=iface, verbose=0, count=5, inter=0.01)

        sess["last_activity_ts"] = time.time()
        sess["retries"][idx] = retries + 1

        if verbose:
            print(f"[FILE-NACK] Retransmitted {session_id} fragment {idx}/{total}, retry {sess['retries'][idx]}")

def user_joined(msg):
    announcement_username = msg.split(":", 1)[1].split("||")[0].strip()
    announcement_room = msg.split(":", 1)[1].split("||")[1].strip()
    announcement_mac = msg.split(":", 1)[1].split("||")[2].strip()
    if verbose:
        print(f"Received announcement from {announcement_username}")
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[!] User {announcement_username} ({announcement_mac}) joined the room.")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()
    room = registry.rooms[announcement_room]
    room.add_member(announcement_mac)

def user_left(msg):
    announcement_username = msg.split(":", 1)[1].split("||")[0].strip()
    announcement_room = msg.split(":", 1)[1].split("||")[1].strip()
    announcement_mac = msg.split(":", 1)[1].split("||")[2].strip()
    if verbose:
        print(f"Received announcement from {announcement_username}")
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[!] User {announcement_username} ({announcement_mac}) left the room.")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()
    room = registry.rooms[announcement_room]
    room.remove_member(announcement_mac)

def get_potential_mac_addresses(iface, blacklist):
    possible_mac_addresses_list = []
    def gpma_packet_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0:
            if pkt.subtype in [1, 5, 8] and pkt.addr2 not in possible_mac_addresses_list:
                possible_mac_addresses_list.append(pkt.addr2)
    print("[Smart-MAC] Sniffing to obtain MAC addresses in use. Please wait.")
    sniff(iface=iface, monitor=True, prn=gpma_packet_handler, store=0, timeout=30)
    if blacklist is None:
        return possible_mac_addresses_list
    else:
        possible_mac_addresses_list.remove(blacklist)
        return possible_mac_addresses_list

def swap_mac_address():
    global persistent_mac, args, iface
    if args.smart_mac:
        print("[Smart-MAC] MAC address is already in use in this room, scanning for a new one...")
        persistent_mac = smart_mac(iface, persistent_mac)
    else:
        print("[!] MAC address is already in use, using a random one instead...")
        persistent_mac = RandMAC()._fix()

def smart_mac(iface, blacklist = None):
    mac_address = ""
    smart_mac_iterations = 0
    blacklist_iterations = 0
    while mac_address == "":
        if smart_mac_iterations > 0:
            print(f"[Smart-MAC] Not enough frames found, starting Smart-MAC process again...")
        elif smart_mac_iterations == 5:
            print(f"[Smart-MAC] Couldn't find any source address in the air. Procceeding with a random MAC.")
            return RandMAC()._fix()
        mac_address_list = get_potential_mac_addresses(iface, blacklist)
        if len(mac_address_list) == 0:
            smart_mac_iterations += 1
        else:
            mac_address = random.choice(mac_address_list)
    print(f"[Smart-MAC] Selected MAC address is {mac_address}")
    return mac_address

def verify_mac_in_use(address):
    for r in registry.all_rooms():
        if address in r.members:
            return True
    return False

def is_duplicate(payload, source_mac):
    try:
        _, msg = decrypt_payload(payload, source_mac)
        if msg and msg.startswith("[RCV-ACK]"):
            return False
    except:
        pass
    digest = sha256(payload).digest()
    if digest in recent_messages:
        return True
    recent_messages.add(digest)
    recent_queue.append(digest)
    if len(recent_messages) > MAX_TRACKED:
        old = recent_queue.popleft()
        recent_messages.remove(old)
    return False

def send_file(path):
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return
    # fragments = fragment_file(path, room_key, room_name, persistent_mac)
    session_id, total_parts, filename, fragments = fragment_file(path, room_key, room_name, persistent_mac)

    tx_sessions_cache[session_id] = {
        "total": total_parts, 
        "filename": filename, 
        "fragments": fragments, 
        "created_ts": time.time(), 
        "last_activity_ts": time.time(), 
        "retries": {}
    }

    #with tqdm(total=len(fragments), desc="Transmitting", unit="frag", ncols=100) as pbar:
    #    for frag in fragments:
    #        pkt = build_packet(frag)
    #        sendp(pkt, monitor=True, iface=iface, verbose=0, count=5, inter=0.01)
    #        pbar.update(1)
    sess = tx_sessions_cache[session_id]

    with tqdm(total=total_parts, desc="Transmitting", unit="frag", ncols=100) as pbar:
        for idx in range(1, total_parts + 1):
            frag = fragments[idx]
            pkt = build_packet(frag)
            sendp(pkt, monitor=True, iface=iface, verbose=0, count=5, inter=0.01)
            sess["last_activity_ts"] = time.time()
            pbar.update(1)

# Pkt reception
def save_file(session_id, fragments_dict, filename):
    ordered = [fragments_dict[i] for i in sorted(fragments_dict.keys())]
    output = b"".join(ordered)
    decompressed = decompress(output)
    file = "recv/recv_" + filename
    with open(file, "wb") as f:
        f.write(decompressed)
    print(f"[+] File received and saved as {file}")

def file_rx_monitor():
    while True:
        now = time.time()

        for session_id, session in list(file_sessions.items()):
            total = session.get("total")
            data = session.get("data", {})
            last_rx = session.get("last_rx_ts", now)
            last_nack = session.get("last_nack_ts", 0.0)
            
            if not total:
                continue

            if len(data) != total and (now - last_rx) >= FILE_IDLE_TOUT and (now - last_nack) >= FILE_NACK_CD:
                missing = [i for i in range(1, total + 1) if i not in data]
                if missing:
                    batch = missing[:FILE_NACK_BATCH]
                    nack_msg = f"{FILE_NACK_HEADER_PREFIX}{session_id}|{','.join(map(str, batch))}"
                    send_plain(nack_msg)
                    session["last_nack_ts"] = now
            
            if len(data) != total and (now - last_rx) > FILE_RX_CLOSE:
                del file_sessions[session_id]
            
        for session_id, sess in list(tx_sessions_cache.items()):
            last = sess.get("last_activity_ts", sess.get("created_ts", now))
            if (now - last) > TX_SESSION_CACHE_TIMER:
                del tx_sessions_cache[session_id]
        
        time.sleep(1)

def is_fragmented_file(payload, source_mac):
    try:
        decrypted = gcm_decrypt(room_key, args.room, source_mac.lower(), payload)
        parts = decrypted.split(b"|", 2)
        if len(parts) < 3:
            return False
        session_id = parts[0].decode(errors="ignore")
        index_info = parts[1].decode(errors="ignore")
        if len(session_id) != 8:
            return False
        current, total = map(int, index_info.split("/"))
        return 1 <= current <= total <= 9999
    except Exception as e:
        return False

def handle_fragment(payload, source_mac):
    global file_sessions
    try:
        decrypted = gcm_decrypt(room_key, args.room, source_mac.lower(), payload)
        session_id, idx, total, filename, content = parse_decrypted(decrypted)
        if None in (session_id, idx, total, filename, content):
            return

        if session_id not in file_sessions:
            file_sessions[session_id] = {
                "total": total, 
                "data": {}, 
                "last_rx_ts": time.time(), 
                "last_nack_ts": 0.0
            }

        session = file_sessions[session_id]
        session["data"][idx] = content
        session["last_rx_ts"] = time.time()

        if idx == 1:
            idx1_msg = f"[+] Receiving {total} fragments for file {filename}"
            sys.stdout.write("\r" + " " * (len(idx1_msg)) + "\r" + idx1_msg + "\n")
            sys.stdout.flush()

        if len(session["data"]) == total:
            save_file(session_id, session["data"], filename)
            send_plain(f"{FILE_ACK_HEADER_PREFIX}{session_id}")
            del file_sessions[session_id]
    except Exception as e:
        print(f"[!] Error processing fragment: {e}")

def packet_handler(pkt):
    global username, persistent_mac, room_name, registry
    if pkt.haslayer(Dot11) and pkt.haslayer(Raw):
        if (pkt.type == 0 and pkt.subtype == 6) or (pkt.type == 0 and pkt.subtype == 9) or (pkt.type == 0 and pkt.subtype == 13) or (pkt.type == 2 and pkt.subtype == 0) or (pkt.type == 2 and pkt.subtype == 8):
            raw_data = pkt[Raw].load
            pkt_src_mac = pkt[Dot11].addr2
            if is_duplicate(raw_data, pkt_src_mac):
                return
            if is_fragmented_file(raw_data, pkt_src_mac): # file transmission
                if not pkt_src_mac == persistent_mac:
                    handle_fragment(raw_data, pkt_src_mac)
            else: # message transmission
                user, msg = decrypt_payload(raw_data, pkt_src_mac)
                if user == username and pkt_src_mac == persistent_mac: # filter own messages (sender + MAC address)
                    return
                if user and msg:
                    if msg.startswith("[RCV-ACK]"):
                        handle_ack(msg)
                    elif msg.startswith("[USR-ANN]"):
                        if verify_mac_in_use(pkt_src_mac):
                            if verbose:
                                print(f"DEBUG: Received annnouncement from {user}, who had an address in use. Requesting him to change his MAC.")
                            request_mac_swap(pkt_src_mac, user)
                        else: 
                            user_joined(msg)
                    elif msg.startswith(FILE_NACK_HEADER_PREFIX):
                        handle_file_nack(msg)
                    elif msg.startswith(FILE_ACK_HEADER_PREFIX):
                        handle_file_ack(msg)
                    elif msg.startswith("[USR-LFT]"):
                        user_left(msg)
                    elif msg.startswith("[USR-HB]"):
                        _, rname, sender = msg.split("||")
                        if verbose:
                            print(f"DEBUG: Received hearbeat from {sender} on {rname}")
                        if rname == room_name:
                            room = registry.rooms[rname]
                            room.add_member(sender)
                            room.heartbeat(sender)
                        return
                    elif msg.startswith("[REQ-MAC]"):
                        if verbose:
                            print(f"DEBUG: Received MAC address change request")
                        if persistent_mac == msg.split("]:")[1]:
                            swap_mac_address()
                            # Re-announcing user
                            announce_user(username, "join")
                    else:
                        if verbose:
                            print(f"DEBUG: Received message from {user} ({pkt_src_mac})")
                        # Check if sender is already a member of the room
                        for r in registry.all_rooms():
                            if pkt_src_mac not in r.members:
                                r.add_member(pkt_src_mac)
                        pretty_printer(user, msg, input_request_message, current_input) # print received packet
                        ack = f"[RCV-ACK]: {checksum(raw_data)}"                        # calculate ACK checksum
                        send_plain(ack)                                                 # and send it back

# Others
def welcome():
    greeting = """

                  ░██        ⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣦⠀               ░██    ░██   ░██              ░██       
                  ░██        ⠀⠀⠀⠀⣰⣿⡟⢻⣿⡟⢻⣧               ░██    ░██ ░████              ░██         
        ░████████ ░████████  ⠀⠀⠀⣰⣿⣿⣇⣸⣿⣇⣸⣿  ░███████  ░████████ ░██   ░██   ░████████  ░██    ░██  
       ░██    ░██ ░██    ░██ ⠀⠀⣴⣿⣿⣿⣿⠟⢻⣿⣿⣿ ░██           ░██    ░██   ░██   ░██    ░██ ░██   ░██   
       ░██    ░██ ░██    ░██ ⣠⣾⣿⣿⣿⣿⣿⣤⣼⣿⣿⠇  ░███████     ░██    ░██   ░██   ░██    ░██ ░███████    
       ░██   ░███ ░██    ░██ ⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠀        ░██    ░██    ░██   ░██   ░██    ░██ ░██   ░██   
        ░█████░██ ░██    ░██ ⠀⠀⠈⠿⠿⠋⠙⢿⣿⡿⠁⠀  ░███████      ░████ ░██ ░██████ ░██    ░██ ░██    ░██  
              ░██                                                                              
        ░███████                                                                               
       """
    print(greeting + "\n")
    print("=" * 100)


# Main
def start_sniffer():
    sniff(iface=iface, monitor=True, prn=packet_handler, store=False)

def input_loop():
    global current_input
    while True:
        try:
            current_input = input(input_request_message)
            if current_input.lower().strip() == "!quit" or current_input.lower().strip() == "!exit" or current_input.lower().strip() == "!bye":
                announce_user(username, "left")
                print("\n[!] Exitting.")
                break
            elif current_input.startswith("!{") and current_input.endswith("}"):
                send_file(current_input[2:-1].strip())
            elif current_input.lower().strip() == "!rooms" or current_input.lower().strip() == "!room":
                for r in registry.all_rooms():
                    if len(r.members) > 1:
                        print(f"Room \"{r.name}\" ({r.visibility}) currently has {str(len(r.members))} clients:")
                    else:
                        print(f"Room \"{r.name}\" ({r.visibility}) currently has {str(len(r.members))} client:")   
                    for member in r.members:
                        print(f"{member} --> {r.last_seen[member]}")                     
                current_input = ""
            elif current_input == "\x0c" or current_input.lower().strip() in ["!clear", "!cls"]:
                subprocess.run(["clear"])
                current_input = ""
                sys.stdout.flush()
            else:
                send_encrypted_msg(current_input)
                current_input = ""
        except KeyboardInterrupt:
            announce_user(username, "left")
            print("\n[!] Exitting.")
            break

if __name__ == "__main__":
    args = argument_parser()

    # Set iface
    iface = args.interface

    # MAC address control
    if args.persistent_mac:
        if valid_mac(args.persistent_mac):
            persistent_mac = str(args.persistent_mac).lower()
        else:
            print(f"[!] {args.persistent_mac} is not a valid MAC address")
            sys.exit(127)
    else:
        if not args.smart_mac:
            persistent_mac = RandMAC()._fix()
        else:
            persistent_mac = smart_mac(iface)

    # Banner
    if not args.bannerless:
        welcome()

    # Verbosity
    if args.verbose:
        verbose = True

    # Visibility
    if not args.room:
        visibility = "public"
    else:
        room_name = args.room
        visibility = "private"

    # Username control    
    if not args.username:
        username = input("[>] Enter your username: ")
    else:
        username = args.username
    
    if "~" in username:
        username = username.replace("~", "-")
    
    # Before final execution & loop
    ## Start permanent daemons
    registry = RoomRegistry()
    threading.Thread(target=prune_loop, daemon=True).start()
    threading.Thread(target=vote_cleanup_loop, daemon=True).start()
    # Channel control
    # channel = Channel(iface, wait=0.75)

    # Register room
    room = registry.get_or_create(room_name, visibility=visibility)

    # Set encoding key
    if visibility == "private":
        room_key = kdf_from_room(args.room)

    # Start receiver
    threading.Thread(target=start_sniffer, daemon=True).start()

    # Start file RX monitor
    threading.Thread(target=file_rx_monitor, daemon=True).start()
    
    # Send user announcement & heartbeat
    announce_user(username, "join")
    threading.Thread(target=send_heartbeat, daemon=True).start()

    # Start message loop
    input_loop()