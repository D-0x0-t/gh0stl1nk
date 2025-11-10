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

import threading
import time
import uuid
import math

active_votes = {}

def quorum(n):
    return math.ceil(0.51 * n)

class Room:
    def __init__(self, name, visibility):
        self.name = name                           # Room name
        self.visibility = visibility               # Room visibility status (public/private)
        self.members = set()                       # Active MACs (clients/members)
        self.last_seen = {}                        # MAC -> last received heartbeat
        self.lock = threading.RLock()              # RLock instead of lock may solve TX storming

    def add_member(self, mac):
        with self.lock:
            if mac not in self.members:
                self.members.add(mac)
                self.last_seen[mac] = time.time()
            else:
                self.last_seen[mac] = time.time()

    def remove_member(self, mac):
        with self.lock:
            if mac in self.members:
                self.members.discard(mac)
                self.last_seen.pop(mac, None)

    def heartbeat(self, mac):
        with self.lock:
            if mac in self.members:
                self.last_seen[mac] = time.time()

    def prune_dead(self, timeout):
        to_remove = []
        now = time.time()
        with self.lock:
            for mac, ts in list(self.last_seen.items()):
                if now - ts > timeout:
                    to_remove.append(mac)
            for mac in to_remove:
                self.members.discard(mac)
                self.last_seen.pop(mac, None)


class RoomRegistry:
    def __init__(self):
        self.rooms = {}  # room_name -> Room
        self.lock = threading.Lock()

    def get_or_create(self, name, visibility) -> Room:
        with self.lock:
            if name not in self.rooms:
                self.rooms[name] = Room(name, visibility)
            return self.rooms[name]

    def get(self, name) -> Room:
        return self.rooms.get(name)

    def all_rooms(self):
        return list(self.rooms.values())


class VoteSession:
    def __init__(self, room, action, initiator, timeout = 15):
        self.id = str(uuid.uuid4())             # Voting session ID
        self.room = room                        # Room ID
        self.action = action                    # Action to do (publish / unpublish)
        self.initiator = initiator              # Initiator MAC address
        self.votes = {}                         # MAC -> bool (True=accept, False=reject)
        self.start_time = time.time()           # Starting timestamp
        self.timeout = timeout                  # Vote session duration

    def cast_vote(self, mac, yes):
        if mac in self.room.members and mac not in self.votes:
            self.votes[mac] = yes

    def is_expired(self):
        return (time.time() - self.start_time) > self.timeout

    def passed(self):
        needed = quorum(len(self.room.members))
        yes_votes = sum(1 for v in self.votes.values() if v)
        return yes_votes >= needed

