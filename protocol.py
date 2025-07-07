# wapa_ghostlink_protocol.py
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
