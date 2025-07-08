# gh0stl1nk.py — WAPA ghostlink
# Copyright (C) 2025 D0t
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import time
import base64
import logging
import os, sys
import threading
from hashlib import sha256
from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from scapy.all import *
from protocol import fragment_file, decrypt_fragment, parse_decrypted

# ==============================
# CONFIGURACIÓN GENERAL (esto tiene que venir parametrizado o cargado desde consola al iniciar, no hardcodeado)
# ==============================
iface = "mon1"                      #| default
username = "d0t"                    #| default
cipher_key = b"mysharedsecret00"    #| default (16 caracteres)
count = 5
maxpayload = 1024
verbose = False

bootime = time.time()º
file_sessions = {}
recent_messages = set()
recent_queue = deque()
MAX_TRACKED = 100
ack_wait = {}  # hash -> timestamp
ack_lock = threading.Lock()
current_input = ""

# ==============================
# UTILIDADES
# ==============================
def pretty_printer(user, msg):
    sys.stdout.write("\r" + " " * (len("mensaje> ") + len(current_input)) + "\r")
    print(f"[{user}]: {msg}")
    sys.stdout.write("mensaje> " + current_input)
    sys.stdout.flush()

def current_timestamp():
    return int((time.time() - bootime) * 1000000)

def checksum(data):
    return sha256(data).hexdigest()[:8]

def chatencrypt(message):
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
    dot11 = Dot11(type=0, subtype=13, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff")
    pkt = RadioTap()/dot11/Raw(load=encrypted_msg)
    pkt.timestamp = current_timestamp()
    return pkt

def wait_for_ack(msg_hash, timeout=1.0, interval=0.05):
    """
    Espera hasta `timeout` segundos a que msg_hash desaparezca de ack_wait.
    Comprueba cada `interval` segundos.
    Devuelve True si llegó el ACK, False si expiró.
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
    Envía un mensaje cifrado pero SIN esperar ACK ni registrarlo.
    Ideal para enviar los [RCV-ACK] y otros mensajes específicos del protocolo Gl1nk.
    """
    encrypted = chatencrypt(msg)
    pkt = build_packet(encrypted)
    for _ in range(count):
        sendp(pkt, iface=iface, verbose=0)

def send_encrypted_msg(msg):
    """
    Envía un mensaje cifrado y retransmite hasta recibir ACK.
    """
    # Mensajes vacíos: sin ACK
    if not msg.strip():
        encrypted = chatencrypt(msg)
        pkt = build_packet(encrypted)
        for _ in range(count):
            sendp(pkt, iface=iface, verbose=0)
        return

    encrypted = chatencrypt(msg)
    pkt       = build_packet(encrypted)
    msg_hash  = checksum(encrypted)

    # Registrar en espera de ACK
    with ack_lock:
        ack_wait[msg_hash] = time.time()
    if verbose:
        print(f"[ghostlink] awaiting ACK for {msg_hash}")

    # Retransmisión + espera
    for attempt in range(count):
        sendp(pkt, iface=iface, verbose=0)
        if verbose:
            print(f"[ghostlink] sent {msg_hash}, attempt {attempt+1}/{count}")

        # Aquí es donde comprobamos realmente la llegada del ACK
        if wait_for_ack(msg_hash, timeout=1.0):
            if verbose:
                print(f"[ACK] received for {msg_hash}")
            break
    else:
        print(f"[✖] No ACK for {msg_hash} after {count} attempts")


def handle_ack(msg):
    if msg.startswith("[RCV-ACK]"):
        ack_hash = msg.split(":", 1)[1].strip()
        with ack_lock:
            if ack_hash in ack_wait:
                if verbose:
                    print(f"[ACK] Confirmación recibida para {ack_hash}, {msg}")
                del ack_wait[ack_hash]

def is_duplicate(payload):
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
        print(f"[!] Archivo no encontrado: {path}")
        return
    fragments = fragment_file(path)
    print(f"[>] Enviando {len(fragments)} fragmentos desde: {path}")
    for i, frag in enumerate(fragments, 1):
        pkt = build_packet(frag)
        sendp(pkt, iface=iface, count=count, verbose=0)
        print(f"  - Fragmento {i}/{len(fragments)} enviado")

# ==============================
# RECEPCION
# ==============================
def save_file(session_id, fragments_dict):
    ordered = [fragments_dict[i] for i in sorted(fragments_dict.keys())]
    output = b"".join(ordered)
    filename = f"ghostlink_recv_{session_id}.bin"
    with open(filename, "wb") as f:
        f.write(output)
    print(f"[✔] Archivo recibido y guardado como: {filename}")

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
        print(f"[+] Fragmento {idx}/{total} recibido para sesión {session_id}")

        if len(session["data"]) == total:
            save_file(session_id, session["data"])
            del file_sessions[session_id]
    except Exception as e:
        print(f"[!] Error al procesar fragmento: {e}")

def packet_handler(pkt):
    global username
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 13 and pkt.haslayer(Raw):
        raw_data = pkt[Raw].load
        if is_duplicate(raw_data):
            return
        if is_fragmented_file(raw_data): # camino específico para archivos
            handle_fragment(raw_data)
        else: # camino específico para mensajería
            user, msg = decrypt_payload(raw_data)
            if user == username: # filtramos mensajes propios
                return
            if user and msg: 
                if msg.startswith("[RCV-ACK]"):
                    handle_ack(msg) 
                else:
                    #print(f"\n[{user}]: {msg}")                 
                    pretty_printer(user, msg)                   # print received packet
                    ack = f"[RCV-ACK]: {checksum(raw_data)}"    # calculate ACK checksum
                    send_plain(ack)                             # and send it back

# ==============================
# MAIN
# ==============================
def start_sniffer():
    sniff(iface=iface, prn=packet_handler, store=False)

def adjust_psk(psk):
    encoded_psk = psk.encode() 
    cipher_key = pad(encoded_psk, AES.block_size)
    return cipher_key[:16]

def input_loop():
    global current_input
    while True:
        try:
            current_input = input("mensaje> ")
            if current_input.lower() == "quit" or current_input.lower() == "exit":
                break
            elif current_input.startswith("!{") and current_input.endswith("}"):
                send_file(current_input[2:-1].strip())
            else:
                send_encrypted_msg(current_input)
                current_input = ""
        except KeyboardInterrupt:
            print("\n[!] Interrumpido por el usuario.")
            break

if __name__ == "__main__":
    greeting = "        [*] Started WAPA gh0stl1nk        "
    print(greeting)
    print("=" * len(greeting))
    iface = input("[>] Select the interface to use: ")
    username = input("[>] Enter your username: ")
    key = input("[>] Enter the room name: ") # ajustar padding a 16
    cipher_key = adjust_psk(key)
    threading.Thread(target=start_sniffer, daemon=True).start()
    input_loop()
