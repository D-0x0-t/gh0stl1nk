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
import datetime
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
import os, sys, re
import threading
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


# ==============================
#       General config
# ==============================
count = 5
maxpayload = 1024
verbose = False
input_request_message = "message> "

bootime = time.time()
file_sessions = {}
recent_messages = set()
recent_queue = deque()
MAX_TRACKED = 100
ack_wait = {}  # hash -> timestamp
ack_lock = threading.Lock()
current_input = ""
HEARTBEAT_INTERVAL = 10

# ==============================
#           Argparse
# ==============================
def argument_parser():
    parser = argparse.ArgumentParser(prog="gh0stl1nk", description="gh0stl1nk console")
    parser.add_argument("interface", help="interface to be used")
    parser.add_argument("-u", "--username", dest="username", help="your name inside gh0stl1nk")
    parser.add_argument("-r", "--room", dest="room", help="directly connect to a room")
    parser.add_argument("-b", "--bannerless", dest="bannerless", default=False, help="disable welcome banner", action="store_true")
    parser.add_argument("-l", "--list", dest="list_rooms", default=False, help="list available rooms", action="store_true")
    parser.add_argument("-m", "--mac", dest="persistent_mac", default=None, help="establish a custom MAC address")
    parser.add_argument("-v", "--visibility", dest="visibility", default="public", choices=["public", "private"], help="Choose room visibility (only if creating it)")

    # args = parser.parse_args()
    return parser.parse_args()   

# ==============================
#            Utils
# ==============================
def send_heartbeat():
    global room_name, persistent_mac
    while True:
        heartbeat_control_msg = f"[USR-HB]||{room_name}||{persistent_mac}||{str(int(time.time()))}"
        send_plain(heartbeat_control_msg)
        time.sleep(HEARTBEAT_INTERVAL)

def prune_loop():
    while True:
        for room in registry.rooms.values():
            room.prune_dead(timeout=30)
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
    """
    Prettify code output with special characters
    """
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[{curtime()}] <{user}>: {msg}")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()

def current_timestamp():
    """
    Get the current time
    """
    return int((time.time() - bootime) * 1000000)

def checksum(data):
    """
    Calculate checksum of messages and return last 5 characters
    """
    return sha256(data).hexdigest()[:8]

def chatencrypt(message):
    """
    Cipher message and encode it with base 64
    """
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
    """
    Decrypt message and return (user, content)
    """
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
    """
    Create 802.11 packet with a payload
    """
    global persistent_mac
    dot11 = Dot11(type=0, subtype=13, addr1="ff:ff:ff:ff:ff:ff", addr2=persistent_mac, addr3="ff:ff:ff:ff:ff:ff")
    pkt = RadioTap()/dot11/Raw(load=encrypted_msg)
    pkt.timestamp = current_timestamp()
    return pkt

def wait_for_ack(msg_hash, timeout=1.0, interval=0.05):
    """
    Wait for ACKs
    Checks again every 'interval' seconds
    If ACK, True, else False
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with ack_lock:
            if msg_hash not in ack_wait:
                return True
        time.sleep(interval)
    return False

def send_plain(msg):
    """
    Sends an encrypted message without waiting for an ACK (announcements).
    """
    encrypted = chatencrypt(msg)
    pkt = build_packet(encrypted)
    sendp(pkt, iface=iface, verbose=0, count=25, inter=0.01)

def announce_user(user, status):
    """
    Announce users in the room/channel (either new users or users that left the channel)
    """
    if status == "join":
        encrypted_ann = chatencrypt("[USR-ANN]:" + str(user))
    elif status == "left":
        encrypted_ann = chatencrypt("[USR-LFT]:" + str(user))
    pkt = build_packet(encrypted_ann)
    sendp(pkt, iface=iface, verbose=0, count=25, inter=0.01)


def send_encrypted_msg(msg):
    """
    Sends the encrypted message and wait for the ACK
    """
    # Empty messages (no ACK)
    if not msg.strip():
        encrypted = chatencrypt(msg)
        pkt = build_packet(encrypted)
        sendp(pkt, iface=iface, verbose=0, count=25, inter=0.01)
        return

    encrypted = chatencrypt(msg)
    pkt       = build_packet(encrypted)
    msg_hash  = checksum(encrypted)

    with ack_lock:
        ack_wait[msg_hash] = time.time()
    if verbose:
        print(f"[ghostlink] awaiting ACK for {msg_hash}")

    for attempt in range(count):
        sendp(pkt, iface=iface, verbose=0, count=5, inter=0.01)
        if verbose:
            print(f"[ghostlink] sent {msg_hash}, attempt {attempt+1}/{count}")

        if wait_for_ack(msg_hash, timeout=1):
            if verbose:
                print(f"[ACK] received for {msg_hash}")
            break
    else:
        print(f"[✖] No ACK for {msg_hash} after {count} attempts")


def handle_ack(msg):
    """
    Manage received ACKs
    """
    if msg.startswith("[RCV-ACK]"):
        ack_hash = msg.split(":", 1)[1].strip()
        with ack_lock:
            if ack_hash in ack_wait:
                if verbose:
                    print(f"[ACK] Confirmación recibida para {ack_hash}, {msg}")
                del ack_wait[ack_hash]

def user_joined(msg):
    """
    Acts when a user joins the room
    """
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[!] User {msg.split(':', 1)[1].strip()} just joined the room.")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()

def user_left(msg):
    """
    Acts when a user leaves the room
    """
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[!] User {msg.split(':', 1)[1].strip()} left the room.")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()

def is_duplicate(payload):
    """
    Check if the message is duplicated
    """
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
    """
    Fragments a source file and sends each fragment {count} times
    """
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return
    fragments = fragment_file(path)
    print(f"[>] Sending {len(fragments)} fragments from: {path}")
    for i, frag in enumerate(fragments, 1):
        pkt = build_packet(frag)
        sendp(pkt, iface=iface, verbose=0, count=5, inter=0.01)
        print(f"  - Fragment {i}/{len(fragments)} sent")
        

# ==============================
#      Package Reception
# ==============================
def save_file(session_id, fragments_dict): # filter own messages --> username + persistent_mac
    """
    Orders received fragments and creates the source file in the destination system
    """
    ordered = [fragments_dict[i] for i in sorted(fragments_dict.keys())]
    output = b"".join(ordered)
    filename = f"ghostlink_recv_{session_id}.bin"
    with open(filename, "wb") as f:
        f.write(output)
    print(f"[+] File received and saved: {filename}")

def is_fragmented_file(payload):
    """
    Checks if the received frame's payload is a fragmented file (or a message)
    """
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
    """
    Manage file fragments
    """
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
        print(f"[+] Fragmento {idx}/{total} recibido para sesión {session_id}")

        if len(session["data"]) == total:
            save_file(session_id, session["data"])
            del file_sessions[session_id]
    except Exception as e:
        print(f"[!] Error al procesar fragmento: {e}")

def packet_handler(pkt):
    """
    Scapy packet handler
    """
    global username, persistent_mac, room_name, registry
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 13 and pkt.haslayer(Raw):
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
                    user_joined(msg)
                elif msg.startswith("[USR-LFT]"):
                    user_left(msg)
                elif msg.startswith("[USR-HB]"):
                    _, rname, sender, _ = msg.split("||")
                    if rname == room_name:
                        room = registry.rooms[rname]
                        room.add_member(sender)
                        room.heartbeat(sender)
                    return
                else:
                    #print(f"\n[{user}]: {msg}")
                    pretty_printer(user, msg)                   # print received packet
                    ack = f"[RCV-ACK]: {checksum(raw_data)}"    # calculate ACK checksum
                    send_plain(ack)                             # and send it back

# ==============================
#           Others
# ==============================
def welcome():
    greeting = """
                                                                                                                                                      
                                                                                                  :#######*+=                                         
                                                                                                  .#############=                                     
                                                                                                           =+######=                                  
                                                                                                               -*#####                                
                                                                                                  :######:.       +####+                              
                                                                                                  :##########+      -####.                            
                                                                                                       ..=######-     *###*                           
                                                                                                            :+####=    .###*                          
                                                                                                               -####.   .*###                         
                                                                                                :*#####+:        +###:    *##=                        
                    ..#%#:.    .--.    .--     .*#%*.       -###*.    ...........            :#############.      =###:    ###=                       
                   +#######*   -##+    ###   +########-   =########: .###########-          #################      =###.   :###                       
                  +##*   :##*  -##=    ###  -###.  .###. -##+    ###      *##:             ###################-     -##*    ###=                      
                  ###     ---  -##+    ###  -##-   *###* -##*             *##.           .#####################.     ###:   :##*                      
                  ###          -####*#*###  -##- .##=##*  =####==         *##.           =#####--#######--######     +##*    ##*.                     
                  ###   ####*. -##########  -##-=#+ :##*    =*#####:      *##.           #####    +###*    *####      ##*    ###.                     
                  ###     +#*. -##+    ###  -####:  :##*        :###.     *##.           ####     -###=     ####      ##*    *#*.                     
                  ###:    *#*  -##+    ###  -###    +##+ =##:    :##=     *##.           ####.    =###=     ####                                      
                  .###*#####+  -##+    ###.  ######*###   ###*-=####      *##.           ####*    #####    *####                                      
                   .+######.   -##+    ###:   :######-     =######-       +##.           ######++#######*+######                                      
                                                                                         #######################                                      
                                                                                         #######################                                      
                               :**:            .***      =**=    **=   **-    =**:       #######################                                      
                               =##-           *####      +###=   ###  :##*   *##.        #######################                                      
                               =##-          ##+###      =####.  ###  :##* .###          #######################                                      
                               =##-          *  ###      =####*  ###  :##*-###           #######################                                      
                               =##-             ###      =##-##* ###  :##*###            #######################                                      
                               =##-             ###      =##.-##-###  :######=           #######################                                      
                               -##-             ###      =##. *#####  :###:*##+          #####= +#######+.:#####                                      
                               =##-             ###      =##. .#####  :##*  *##*         ###=     *###*.    =###                                      
                               =#########=  -#########-  =##.  -###%  :##*   +##%        ##        :#:        ##                                      
                               -#########=  -#########-  =##.   =###  :##*    =##*
        """
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


# ==============================
# MAIN
# ==============================
def start_sniffer():
    """
    Starts the Scapy sniffer
    """
    sniff(iface=iface, prn=packet_handler, store=False)

def adjust_psk(psk):
    """
    Adjust the cipher_key generated from the room name
    """
    encoded_psk = psk.encode() 
    cipher_key = pad(encoded_psk, AES.block_size)
    return cipher_key[:16]

def input_loop():
    """
    Waits for input and decides what to do with it
    """
    global current_input
    while True:
        try:
            current_input = input(input_request_message)
            if current_input.lower() == "!quit" or current_input.lower() == "!exit" or current_input.lower() == "!bye":
                announce_user(username, "left")
                print("\n[!] Exitting.")
                break
            elif current_input.startswith("!{") and current_input.endswith("}"):
                send_file(current_input[2:-1].strip())
            else:
                send_encrypted_msg(current_input)
                current_input = ""
        except KeyboardInterrupt:
            announce_user(username, "left")
            print("\n[!] Exitting.")
            break

if __name__ == "__main__":
    args = argument_parser()

    # add verbosity to show the actual mac address
    if args.persistent_mac:
        if valid_mac(args.persistent_mac):
            persistent_mac = str(args.persistent_mac).lower()
        else:
            print(f"[!] {args.persistent_mac} is not a valid MAC address")
            sys.exit(127)
    else:
        persistent_mac = RandMAC()._fix()
    
    # revisión de la interfaz
    iface = args.interface
    if args.bannerless is False:
        welcome()

    if not args.room:
        print("flujo de control, no room, se listan rooms activas y espera")
    else:
        room_name = args.room
        visibility = args.visibility
        if not args.username:
            username = input("[>] Enter your username: ")
        else:
            username = args.username
        
        ## Before final execution & loop
        # Start permanent daemons
        registry = RoomRegistry()
        threading.Thread(target=prune_loop, daemon=True).start()
        threading.Thread(target=vote_cleanup_loop, daemon=True).start()

        # Register room
        if visibility == "public":
            # todo: implementar lógica por argumentos para salas privadas
            room = registry.get_or_create(room_name, visibility=visibility) # all rooms are public by default
            room.add_member(persistent_mac)
        # private room workflow

        # Set encoding key
        cipher_key = adjust_psk(room_name) # adjust padding to 16

        # Start receiver
        threading.Thread(target=start_sniffer, daemon=True).start()
        
        # Send user announcement
        announce_user(username, "join")
        threading.Thread(target=send_heartbeat, daemon=True).start()
        input_loop()
