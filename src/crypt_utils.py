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

import hmac, hashlib, math, base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def checksum(data):
    return hashlib.sha256(data).hexdigest()[:8]

def hkdf_sha256(ikm, salt, info, length = 32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, info = b"", b"", b""
    n = math.ceil(length / hashlib.sha256().digest_size)
    for counter in range(1, n+1):
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def kdf_from_room(room_name):
    salt = hashlib.sha256(b"gh0stl1nk|" + room_name.encode()).digest()
    return hkdf_sha256(room_name.encode(), salt, 32)

# Additional Authenticated Data
def gen_aad(room_name, sender_mac):
    mac = (sender_mac or "").lower()
    return f"room={room_name}|mac={mac}".encode()

# Final functions
def gcm_encrypt(room_key, room_name, sender_mac, plaintext):
    nonce = get_random_bytes(12)
    cipher = AES.new(room_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(gen_aad(room_name, sender_mac))
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(nonce + ct + tag)

def gcm_decrypt(room_key, room_name, sender_mac, blob):
    raw = base64.b64decode(blob)
    if len(raw) < 12+16:
        return None
    nonce = raw[:12]
    tag = raw[-16:]
    ct = raw[12:-16]
    cipher = AES.new(room_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(gen_aad(room_name, sender_mac))
    return cipher.decrypt_and_verify(ct, tag)