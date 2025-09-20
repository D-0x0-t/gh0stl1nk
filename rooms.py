import threading
import time
import uuid
import math

active_votes = {}

def quorum(n: int) -> int:
    return math.ceil(0.51 * n)

class Room:
    def __init__(self, name: str, visibility: str = "public"):
        self.name = name                           # Room name
        self.visibility = visibility               # Room visibility status (public/private)
        self.members = set()                       # Active MACs (clients/members)
        self.last_seen = {}                        # MAC -> last received heartbeat
        self.lock = threading.RLock()              # RLock instead of lock may solve TX storming

    def add_member(self, mac: str):
        with self.lock:
            if mac not in self.members:
                self.members.add(mac)
                self.last_seen[mac] = time.time()
            else:
                self.last_seen[mac] = time.time()

    def remove_member(self, mac: str):
        with self.lock:
            if mac in self.members:
                self.members.discard(mac)
                self.last_seen.pop(mac, None)

    def heartbeat(self, mac: str):
        with self.lock:
            if mac in self.members:
                self.last_seen[mac] = time.time()

    def prune_dead(self, timeout: float):
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

    def get_or_create(self, name: str, visibility: str = "public") -> Room:
        with self.lock:
            if name not in self.rooms:
                self.rooms[name] = Room(name, visibility)
            return self.rooms[name]

    def get(self, name: str) -> Room:
        return self.rooms.get(name)

    def all_rooms(self):
        return list(self.rooms.values())


class VoteSession:
    def __init__(self, room: Room, action: str, initiator: str, timeout: float = 15):
        self.id = str(uuid.uuid4())             # Voting session ID
        self.room = room                        # Room ID
        self.action = action                    # Action to do (publish / unpublish)
        self.initiator = initiator              # Initiator MAC address
        self.votes = {}                         # MAC -> bool (True=accept, False=reject)
        self.start_time = time.time()           # Starting timestamp
        self.timeout = timeout                  # Vote session duration

    def cast_vote(self, mac: str, yes: bool):
        if mac in self.room.members and mac not in self.votes:
            self.votes[mac] = yes

    def is_expired(self) -> bool:
        return (time.time() - self.start_time) > self.timeout

    def passed(self) -> bool:
        needed = quorum(len(self.room.members))
        yes_votes = sum(1 for v in self.votes.values() if v)
        return yes_votes >= needed

