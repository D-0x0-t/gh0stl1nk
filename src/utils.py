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

from datetime import datetime
import re
import sys
import time

def curtime():
    return str(datetime.now()).split(".")[0].split(" ")[1]

def valid_mac(address):
    pattern = re.compile(r'^([0-9A-Fa-f]{2}(:)){5}[0-9A-Fa-f]{2}$')
    return bool(pattern.match(address))

def pretty_printer(user, msg, input_request_message, current_input):
    sys.stdout.write("\r" + " " * (len(input_request_message) + len(current_input)) + "\r")
    print(f"[{curtime()}] <{user}>: {msg}")
    sys.stdout.write(input_request_message + current_input)
    sys.stdout.flush()

def sender_pretty_printer(user, msg):
    sys.stdout.write('\r\x1b[2K')
    sys.stdout.write('\x1b[1A\x1b[2K')
    sys.stdout.write(f"[{curtime()}] <{user}>: {msg}\n")
    sys.stdout.flush()

def wait_for_ack(msg_hash, ack_wait, ack_lock, timeout=1.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with ack_lock:
            if msg_hash not in ack_wait:
                return True
        time.sleep(interval)
    return False