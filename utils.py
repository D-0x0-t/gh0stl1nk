import time
import sys
import re
import os
import base64
import threading
from datetime import datetime
from hashlib import sha256
from collections import deque
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import RadioTap, Dot11, Raw, sendp
from scapy.layers.dot11 import Dot11, Dot11Elt, DOt11Beacon, RadioTap
from protocol import *

maxpayload = 1024

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

def chat_encrypt(username, message, cipher_key):
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

def decrypt_payload(data, cipher_key):
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
    pkt = RadioTap()/dot11/Dot11Action(category=69)/Raw(load=encrypted_msg)
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

def send_plain(user, msg):
    """
    Sends an encrypted message without waiting for an ACK (announcements).
    """
    encrypted = chat_encrypt(user, msg, )
    pkt = build_packet(encrypted)
    for _ in range(count):
        sendp(pkt, monitor=True, iface=iface, verbose=0)

def send_encrypted_msg(user, msg):
    """
    Sends the encrypted message and wait for the ACK
    """
    # Empty messages (no ACK)
    if not msg.strip():
        encrypted = chat_encrypt(user, msg)
        pkt = build_packet(encrypted)
        for _ in range(count):
            sendp(pkt, monitor=True, iface=iface, verbose=0)
        return

    encrypted = chat_encrypt(user, msg)
    pkt       = build_packet(encrypted)
    msg_hash  = checksum(encrypted)

    with ack_lock:
        ack_wait[msg_hash] = time.time()
    if verbose:
        print(f"[ghostlink] awaiting ACK for {msg_hash}")

    for attempt in range(count):
        sendp(pkt, monitor=True, iface=iface, verbose=0)
        if verbose:
            print(f"[ghostlink] sent {msg_hash}, attempt {attempt+1}/{count}")

        if wait_for_ack(msg_hash, timeout=1.0):
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
        sendp(pkt, monitor=True, iface=iface, count=count, verbose=0)
        print(f"  - Fragment {i}/{len(fragments)} sent")


# =========================
# Beacon anouncement # testing
# =========================
def create_beacon_frame(room_name, bssid_mac_address):
    essid_name = f"GL-R00m: {str(room_name)}"
    essid = Dot11Elt(ID="SSID", info=essid_name, len=len(essid_name))
    dot11 = Dot11(proto=0, type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid_mac_address, addr3=bssid_mac_address)
    beacon = DOt11Beacon(cap="ESS+privacy")
    rsn = Dot11Elt(ID="RSNinfo", info=(
        b"\x01\x00"
        b"\x00\x0f\xac\x02"
        b"\x02\x00"
        b"\x00\x0f\xac\x04"
        b"\x00\x0f\xac\x02"
        b"\x01\x00"
        b"\x00\x0f\xac\x02"
        b"\x00\x00"
    ))

    dsset = Dot11Elt(ID="DSset",info="\x01")
    tim = Dot11Elt(ID="TIM",info="\x00\x01\x00\x00") # Traffic Indication Map
    rates = Dot11Elt(ID="Rates",info="\x02\x04\x0b\x16\x0c\x12\x18\x24\x30\x48\x60\x6c") # Modern rates for WiFi networks

    return RadioTap()/dot11/beacon/essid/rsn/rates/dsset/tim