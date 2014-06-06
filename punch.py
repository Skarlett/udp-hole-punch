#
# Imports
#
import string
import random
import socket
import json
import time

#
# Constants
#
SESSION_RETRIES = 4
INIT_TIMEOUT = 10
SESSION_DURATION = 10

#
# Timeout
#
class Timeout(Exception):
    def __init__(self):
        return Exception.__init__(self, "timed out")

#
# Secret generation
#
def generate_secret():
    return "".join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        for _ in range(32)
    )

#
# JSON encode/decode
#
def decode(m):
    return json.loads(m.decode("utf8"))

def encode(m):
    return json.dumps(m).encode("utf8")

#
# STUN-esque server
#
class Server:
    def __init__(self, pair):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(pair)
        self._sessions = {}
    
    def send_reply(self, addr, candidates, host):
        self._socket.sendto(encode({
            "type": "session",
            "candidates": [{"ip": c[0], "port": c[1]} for c in candidates],
            "host": host
        }), addr)
        
    
    def main(self):
        while True:
            try:
                data, addr = self._socket.recvfrom(1024)
                m = decode(data)
                if m["type"] == "request":
                    cs = [(c["ip"], c["port"]) for c in m["local"]]
                    secret = m["secret"]
                    if secret in self._sessions and time.time() - self._sessions[secret][0] < SESSION_DURATION:
                        _, other, othercs = self._sessions[secret]
                        self.send_reply(addr, [other] + othercs, True)
                        self.send_reply(other, [addr] + cs, False)
                        del self._sessions[secret]
                    else:
                        self._socket.sendto(encode({
                            "type": "wait",
                            "expires": SESSION_DURATION
                        }), addr)
                        self._sessions[secret] = (time.time(), addr, cs)
            except Exception as e:
                print("ERR", e)

#
# Session
#
class Session:
    def __init__(self, server, sock = None, secret = None):
        if sock is None: sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if secret is None: secret = generate_secret()
        self._socket     = sock
        self._server     = server
        self._secret     = secret
        self._done       = False
        self._candidates = None
        self._host       = None

    def get_secret(self):
        return self._secret

    def get_candidates(self):
        if not self._done:
            self._get_remote()
        return self._candidates

    def is_host(self):
        if not self._done:
            self._get_remote()
        return self._host

    def get_socket(self):
        return self._socket
    
    def _recv(self, size, timeout):
        old_delay = self._socket.gettimeout()
        self._socket.settimeout(timeout)
        try:
            data, addr = self._socket.recvfrom(size)
            return decode(data), addr
        except ValueError: # oh god what a terrible hack
            return self._recv(size, timeout)
        finally:
            self._socket.settimeout(old_delay)
    
    def _send(self, addr, data):
        self._socket.sendto(encode(data), addr)

    def _get_remote(self):
        if not self._done:
            retries = 0
            while retries < SESSION_RETRIES:
                try:
                    # … what a terrible way of getting the local IP
                    self._send(self._server, {"type": "ignore"})
                    sn = self._socket.getsockname()
                    self._send(self._server, {
                        "type": "request",
                        "secret": self._secret,
                        "local": [{
                            "ip": sn[0],
                            "port": sn[1]
                        }]
                    })
                    data, addr = self._recv(1024, INIT_TIMEOUT)
                    if data["type"] == "wait":
                        data, addr = self._recv(1024, data["expires"])
                    if data["type"] == "session":
                        self._candidates = [(c["ip"], c["port"]) for c in data["candidates"]]
                        self._host = data["host"]
                        self._done = True
                    return
                except socket.timeout:
                    pass
                finally:
                    retries += 1
        raise Timeout()

#
# Connection
#
class Connection:
    def __init__(self):
        self._got_confirm  = False
        self._sent_confirm = False
        self._session      = None
        self._socket       = None
        self._target       = None
        self._hold         = []
    
    def _handle_control(self, addr, data):
        print(addr, data)
        if data == b"PUNCH":
            self._target = addr
            self._sent_confirm = True
            self._send_control(b"CONFIRM")
            if not self._got_confirm:
                self._send_control(b"PUNCH")
        elif data == b"CONFIRM":
            self._got_confirm = True

    def _punch(self):
        self._socket = self._session.get_socket()
        cs = self._session.get_candidates()
        for c in cs:
            self._send_control(b"PUNCH", target = c)
        while not self._sent_confirm or not self._got_confirm:
            self._recv_control()
    
    def send(self, data):
        self._send(b"1" + data)
    
    def _send_control(self, data, target = None):
        self._send(b"0" + data, target)

    def _send(self, data, target = None):
        if target is None:
            target = self._target
        self._socket.sendto(data, target)
    
    def recv(self, size):
        while True:
            data = self._recv(size)
            if data is not None:
                return data
    
    def _recv_control(self):
        while True:
            data = self._recv(1024)
            if data is not None:
                self._hold.append(data)
            else:
                return

    def _recv(self, size):
        if len(self._hold) > 0:
            return self._hold.pop(0)
        data, addr = self._socket.recvfrom(size)
        if data.startswith(b"0"): # control
            self._handle_control(addr, data[1:])
            return None
        elif data.startswith(b"1"): # data
            return data[1:]

    def connect(self, session):
        self._session = session
        self._punch()
