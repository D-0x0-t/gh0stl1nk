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

import subprocess
import threading
import random
import re
from time import sleep

class Channel(threading.Thread):
    def __init__(self, interface, wait=0.5):
        super().__init__(daemon=True)
        self.interface = interface
        self.wait = wait
        self.running = threading.Event()
        self.running.set()
        self.lock = threading.Lock()
        self.current_channel = None
        self.channels = self.get_channel_list()

    def get_channel_list(self):
        try:
            command = subprocess.check_output(["iwlist", self.interface, "channel"], text=True)
            channels = re.findall(r"Channel\s+(\d+)", command)
            return sorted(set(map(int, channels)))
        except OSError as e:
            print("[!] Error", e)
            return list(range(1, 14))
    
    def set_channel(self, channel):
        with self.lock:
            subprocess.run(["iw", "dev", self.interface, "set", "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            self.current_channel = channel

    def run(self):
        while self.running.is_set():
            channel = random.choice(self.channels)
            self.set_channel(channel)
            sleep(self.wait)

    def stop(self):
        self.running.clear()

    def fix_channel(self, channel):
        self.stop()
        self.set_channel(channel)