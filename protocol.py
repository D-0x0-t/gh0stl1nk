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

# Lógica de cifrado, fragmentación y empaquetado para Ghostlink

import base64
import os
import uuid
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = AES.block_size
MAX_PAYLOAD = 1024  # Ajustable según MTU efectiva
CIPHER_KEY = b"mysharedsecret00"  # 16 bytes

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
    session_id = uuid.uuid4().hex[:8]  # ID corto de sesión
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
