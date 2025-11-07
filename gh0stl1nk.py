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
from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from scapy.all import *

# Gh0stl1nk internals
from protocol import fragment_file, decrypt_fragment, parse_decrypted
from rooms import RoomRegistry, VoteSession, active_votes
from rooms import quorum
from src.channel_hop import Channel
from src.carriers import *

#
## General config
#
count = 10
maxpayload = 1024
verbose = False
input_request_message = "message> "

bootime = time.time()
file_sessions = {}
recent_messages = set()
recent_queue = deque()
MAX_TRACKED = 100
ack_wait = {}
ack_lock = threading.Lock()
current_input = ""
HEARTBEAT_INTERVAL = 30

#
## Argparse
#
def argument_parser():
    parser = argparse.ArgumentParser(prog="gh0stl1nk", description="gh0stl1nk console")
    parser.add_argument("interface", help="interface to be used")
    parser.add_argument("-b", "--bannerless", dest="bannerless", default=False, help="disable welcome banner", action="store_true")
    # parser.add_argument("-l", "--list", dest="list_rooms", default=False, help="list available rooms and exit", action="store_true")
    parser.add_argument("-m", "--mac", dest="persistent_mac", default=None, help="establish a custom MAC address")
    parser.add_argument("-r", "--room", dest="room", help="directly connect to a room")
    parser.add_argument("-s", "--smart-mac", dest="smart_mac", help="cover your MAC address based on the environment", action="store_true")
    parser.add_argument("-u", "--username", dest="username", help="your name inside gh0stl1nk")
    parser.add_argument("-v", "--visibility", dest="visibility", default="public", choices=["public", "private"], help="Choose room visibility (only if creating it)")
    # parser.add_argument("--monitor", help="monitors the air searching for covert communications")
    parser.add_argument("--verbose", dest="verbose", default=False, help="set verbosity to True", action="store_true")
    return parser.parse_args()   

#
## Utils
#
def send_heartbeat():
    global room_name, persistent_mac
    while True:
        heartbeat_control_msg = f"[USR-HB]||{room_name}||{persistent_mac}" # f"[USR-HB]||{room_name}||{persistent_mac}||{str(int(time.time()))}"
        send_plain(heartbeat_control_msg)
        if verbose:
            print(f"DEBUG: Sent heartbeat for room {room_name} and MAC {persistent_mac}")
        room = registry.rooms[room_name]
        room.add_member(persistent_mac)
        time.sleep(HEARTBEAT_INTERVAL)

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

def curtime():
    return str(datetime.now()).split(".")[0].split(" ")[1]

def valid_mac(address):
    pattern = re.compile(r'^([0-9A-Fa-f]{2}(:)){5}[0-9A-Fa-f]{2}$')
    return bool(pattern.match(address))

def pretty_printer(user, msg):
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[{curtime()}] <{user}>: {msg}")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()

def sender_pretty_printer(user, msg):
    sys.stdout.write('\r\x1b[2K')
    sys.stdout.write('\x1b[1A\x1b[2K')
    sys.stdout.write(f"[{curtime()}] <{user}>: {msg}\n")
    sys.stdout.flush()

def current_timestamp():
    return int((time.time() - bootime) * 1000000)

def checksum(data):
    return sha256(data).hexdigest()[:8]

def chat_encrypt(message):
    message = username + "~" + message
    if len(message) < maxpayload:
        message = message.rjust(maxpayload)
    else:
        message = message[:maxpayload]

    iv = get_random_bytes(16)
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    padded = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext)

def decrypt_payload(data):
    try:
        raw = base64.b64decode(data)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode(errors="ignore")
        if "~" in plaintext:
            return plaintext.strip().split("~", 1)
    except:
        pass
    return None, None

def build_packet(encrypted_msg):
    global persistent_mac
    # dot11 = Dot11(type=0, subtype=13, addr1="ff:ff:ff:ff:ff:ff", addr2=persistent_mac, addr3="ff:ff:ff:ff:ff:ff")
    # pkt = RadioTap()/dot11/Dot11Action(category=4)/Raw(load=encrypted_msg)
    # pkt.timestamp = current_timestamp()
    # New workflow with more carriers:
    random_carrier = random.randint(0, 5)
    # random_carrier = 2
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

def wait_for_ack(msg_hash, timeout=1.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with ack_lock:
            if msg_hash not in ack_wait:
                return True
        time.sleep(interval)
    return False

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
    # Empty messages (no ACK)
    if not msg.strip():
        # excluded empty messages from the sender
        # encrypted = chat_encrypt(msg)
        # pkt = build_packet(encrypted)
        # sendp(pkt, monitor=True, iface=iface, verbose=0, count=10, inter=0.01)
        return

    encrypted = chat_encrypt(msg)
    pkt       = build_packet(encrypted)
    msg_hash  = checksum(encrypted)

    with ack_lock:
        ack_wait[msg_hash] = time.time()
    if verbose:
        print(f"[ghostlink] awaiting ACK for {msg_hash}")

    for attempt in range(count): # modificado para evitar recursividad de envíos
        sendp(pkt, monitor=True, iface=iface, verbose=0, count=1, inter=0.01)
        sender_pretty_printer("You", current_input)
        if verbose:
            print(f"[ghostlink] sent {msg_hash}, attempt {attempt+1}/{count}")

        if wait_for_ack(msg_hash, timeout=0.25):
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

def user_joined(msg): # [USR-XYZ]: {user}||{room_name}||{persistent_mac} # responder a este mensaje con confirmación de disponibilidad de la MAC. Si está disponible, nada, si NO está disponible, solicitar cambio.
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
    # perform a quick scan, extract mac addresses and use one of them randomly. 
    # After joining the room, we must check for this MAC being already in use. 
    # If True, then swap the MAC to another one
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

def is_duplicate(payload):
    try:
        _, msg = decrypt_payload(payload)
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
    fragments = fragment_file(path)
    print(f"[>] Sending {len(fragments)} fragments from: {path}")
    for i, frag in enumerate(fragments, 1):
        pkt = build_packet(frag)
        sendp(pkt, monitor=True, iface=iface, verbose=0, count=5, inter=0.01) # 5 envíos por fragmento para evitar colapsos
        print(f"  - Fragment {i}/{len(fragments)} sent")
        

#
## Package Reception
#
def save_file(session_id, fragments_dict): # filter own messages --> username + persistent_mac
    ordered = [fragments_dict[i] for i in sorted(fragments_dict.keys())]
    output = b"".join(ordered)
    filename = f"ghostlink_recv_{session_id}.bin"
    with open(filename, "wb") as f:
        f.write(output)
    print(f"[+] File received and saved: {filename}")

def is_fragmented_file(payload):
    try:
        decrypted = decrypt_fragment(payload)
        parts = decrypted.split(b"|", 2)
        if len(parts) < 3:
            return False
        session_id = parts[0].decode(errors="ignore")
        index_info = parts[1].decode(errors="ignore")
        if len(session_id) != 8:
            return False
        current, total = map(int, index_info.split("/"))
        return 1 <= current <= total <= 9999
    except:
        return False

def handle_fragment(payload_b64):
    global file_sessions
    try:
        decrypted = decrypt_fragment(payload_b64)
        session_id, idx, total, content = parse_decrypted(decrypted)
        if None in (session_id, idx, total, content):
            return

        if session_id not in file_sessions:
            file_sessions[session_id] = {"total": total, "data": {}}

        session = file_sessions[session_id]
        session["data"][idx] = content
        print(f"[+] Fragment {idx}/{total} received for session ID: {session_id}")

        if len(session["data"]) == total:
            save_file(session_id, session["data"])
            del file_sessions[session_id]
    except Exception as e:
        print(f"[!] Error processing fragment: {e}")

def packet_handler(pkt):
    global username, persistent_mac, room_name, registry
    if pkt.haslayer(Dot11) and pkt.haslayer(Raw):
        if (pkt.type == 0 and pkt.subtype == 6) or (pkt.type == 0 and pkt.subtype == 9) or (pkt.type == 0 and pkt.subtype == 13) or (pkt.type == 2 and pkt.subtype == 0) or (pkt.type == 2 and pkt.subtype == 8):
            raw_data = pkt[Raw].load
            if is_duplicate(raw_data):
                return
            if is_fragmented_file(raw_data): # file transmission
                handle_fragment(raw_data)
            else: # message transmission
                user, msg = decrypt_payload(raw_data)
                if user == username and pkt[Dot11].addr2 == persistent_mac: # filter own messages (sender + MAC address)
                    return
                if user and msg: 
                    if msg.startswith("[RCV-ACK]"):
                        handle_ack(msg)
                    elif msg.startswith("[USR-ANN]"):
                        if verify_mac_in_use(pkt[Dot11].addr2):
                            if verbose:
                                print(f"DEBUG: Received annnouncement from {user}, who had an address in use. Requesting him to change his MAC.")
                            request_mac_swap(pkt[Dot11].addr2, user)
                        else: 
                            user_joined(msg)
                    elif msg.startswith("[USR-LFT]"):
                        user_left(msg)
                    elif msg.startswith("[USR-HB]"): # [USR-HB]||test||de:ad:be:ef:34:34||1758401590
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
                            print(f"DEBUG: Received message from {user} ({pkt[Dot11].addr2})")
                        # Check if sender is already a member of the room
                        for r in registry.all_rooms():
                            if pkt[Dot11].addr2 not in r.members:
                                r.add_member(pkt[Dot11].addr2)
                        pretty_printer(user, msg)                   # print received packet
                        ack = f"[RCV-ACK]: {checksum(raw_data)}"    # calculate ACK checksum
                        send_plain(ack)                             # and send it back

#
## Others
#
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


#
## MAIN
#
def start_sniffer():
    sniff(iface=iface, monitor=True, prn=packet_handler, store=False)

def adjust_psk(psk):
    encoded_psk = psk.encode() 
    cipher_key = pad(encoded_psk, AES.block_size)
    return cipher_key[:16]

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
                print(f"Listing rooms:")
                for r in registry.all_rooms():
                    if len(r.members) > 1:
                        print(f"Room \"{r.name}\" ({r.visibility}) currently has {str(len(r.members))} clients:")
                    else:
                        print(f"Room \"{r.name}\" ({r.visibility}) currently has {str(len(r.members))} client:")   
                    for member in r.members:
                        print(f"{member} --> {r.last_seen[member]}")                     
                    #for member in r.last_seen.keys():
                    #    print(f"{member} --> {r.last_seen[member]}")
                    #print(f"Name: {r.name}\nMembers -> {sorted(r.members)}\nTimers -> {r.last_seen}\nVisibility: {r.visibility}")
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

    # revisión de la interfaz
    iface = args.interface

    # add verbosity to show the actual mac address
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

    if not args.bannerless:
        welcome()

    if args.verbose:
        verbose = True

    if not args.room:
        print("flujo de control, no room, se listan rooms activas y espera")
    else:
        room_name = args.room
        visibility = args.visibility
        if not args.username:
            username = input("[>] Enter your username: ")
        else:
            username = args.username
        
        if "~" in username:
            username = username.replace("~", "-")
        
        ## Before final execution & loop
        # Start permanent daemons
        registry = RoomRegistry()
        threading.Thread(target=prune_loop, daemon=True).start()
        threading.Thread(target=vote_cleanup_loop, daemon=True).start()
        # Channel control
        # channel = Channel(iface, wait=0.75)

        # Register room
        if visibility == "public":
            # todo: implementar lógica por argumentos para salas privadas
            room = registry.get_or_create(room_name, visibility=visibility) # all rooms are public by default
        # private room workflow

        # Set encoding key
        cipher_key = adjust_psk(room_name) # adjust padding to 16

        # Start receiver
        threading.Thread(target=start_sniffer, daemon=True).start()
        
        # Send user announcement
        announce_user(username, "join")
        threading.Thread(target=send_heartbeat, daemon=True).start()
        input_loop()