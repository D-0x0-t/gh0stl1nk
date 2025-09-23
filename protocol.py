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

import base64
import os
import uuid
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = AES.block_size
MAX_PAYLOAD = 1024

# =========================
# Cifrado / Descifrado
# =========================

def encrypt_fragment(fragment: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(CIPHER_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(fragment, BLOCK_SIZE))
    return base64.b64encode(iv + ciphertext)


def decrypt_fragment(payload_b64: bytes) -> bytes:
    raw = base64.b64decode(payload_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(CIPHER_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

# =========================
# Fragmentación de ficheros
# =========================

def fragment_file(file_path: str) -> list[bytes]:
    with open(file_path, "rb") as f:
        content = f.read()
    session_id = uuid.uuid4().hex[:8]
    chunks = []
    max_data = MAX_PAYLOAD - 32  # Reservamos para metadatos

    total_parts = (len(content) + max_data - 1) // max_data

    for i in range(total_parts):
        part = content[i * max_data:(i + 1) * max_data]
        header = f"{session_id}|{i+1}/{total_parts}|".encode()
        chunks.append(encrypt_fragment(header + part))

    return chunks

# =========================
# Parseo de fragmentos
# =========================

def parse_decrypted(decrypted: bytes):
    try:
        meta, raw = decrypted.split(b"|", 2)[:2], decrypted.split(b"|", 2)[2]
        session_id = meta[0].decode()
        current, total = map(int, meta[1].decode().split("/"))
        return session_id, current, total, raw
    except Exception:
        return None, None, None, None
