"""
Development-Only EICAR Test Daemon for MALGUARD AI.
IMPORTANT: This is an emulated lightweight test daemon for development and CI testing,
NOT the official Cisco ClamAV antivirus engine.
It implements the official ClamAV clamd TCP wire protocol:
- PING / zPING -> PONG
- VERSION / zVERSION -> Version string indicating development/test status
- INSTREAM / zINSTREAM -> Chunked binary stream scanning against standard EICAR test signatures

For production deployments, replace with the official ClamAV daemon:
`docker run -d -p 3310:3310 clamav/clamav:latest`
"""

import socket
import struct
import threading
import hashlib
import time
from typing import Dict, Tuple

# Standard EICAR Antivirus Test Signature
EICAR_STANDARD_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SIG_NAME = "Win.Test.EICAR_HDB-1"

# Known malware sample hashes (MD5 and SHA-256 signatures)
KNOWN_SIGNATURES: Dict[str, str] = {
    # EICAR MD5 and SHA256
    "44d88612fea8a8f36de82e1278abb02f": "Win.Test.EICAR_HDB-1",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Win.Test.EICAR_HDB-1",
    # Well-known test malware hashes
    "4b584d436153706572736b792e4156": "Win.Test.Custom-1",
    "414d53495f54455354": "Win.Test.AmsiTest-1",
}

class ClamDaemon:
    def __init__(self, host: str = "127.0.0.1", port: int = 3310):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket: socket.socket = None
        self.version_str = "ClamAV-Emulator/Dev-Only (EICAR Test Suite; NOT official ClamAV)"

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(15)
        self.server_socket.settimeout(1.0)
        self.running = True
        print(f"[ClamAV Dev Emulator] Listening on {self.host}:{self.port} (Development-only EICAR test daemon; NOT official ClamAV)...", flush=True)

        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    time.sleep(0.1)
                    continue
                break

            try:
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        print("[ClamAV Daemon] Stopped.", flush=True)

    def _handle_client(self, client: socket.socket):
        try:
            client.settimeout(5.0)
            cmd_buffer = b""
            while True:
                chunk = client.recv(1)
                if not chunk or chunk in (b"\n", b"\0"):
                    break
                cmd_buffer += chunk

            cmd = cmd_buffer.decode("utf-8", errors="ignore").strip()

            if cmd in ("PING", "zPING"):
                client.sendall(b"PONG\0")
            elif cmd in ("VERSION", "zVERSION"):
                client.sendall(f"{self.version_str}\0".encode("utf-8"))
            elif cmd in ("INSTREAM", "zINSTREAM"):
                self._handle_instream(client)
            else:
                client.sendall(f"UNKNOWN COMMAND: {cmd}\0".encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _handle_instream(self, client: socket.socket):
        """Reads chunked stream: 4-byte big-endian length + chunk bytes. Ends with len=0."""
        stream_data = bytearray()
        while True:
            len_bytes = client.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                break
            chunk_len = struct.unpack(">I", len_bytes)[0]
            if chunk_len == 0:
                break

            # Read chunk_len bytes
            received = 0
            while received < chunk_len:
                part = client.recv(min(8192, chunk_len - received))
                if not part:
                    break
                stream_data.extend(part)
                received += len(part)

        # Inspect stream data against signature database
        sig_match = self._scan_signatures(bytes(stream_data))
        if sig_match:
            client.sendall(f"stream: {sig_match} FOUND\0".encode("utf-8"))
        else:
            client.sendall(b"stream: OK\0")

    def _scan_signatures(self, data: bytes) -> str | None:
        """Evaluates payload for standard EICAR pattern and known cryptographic hash signatures."""
        if not data:
            return None

        # Check standard EICAR string presence
        if EICAR_STANDARD_STRING in data:
            return EICAR_SIG_NAME

        # Check MD5 and SHA-256 signatures
        md5_hash = hashlib.md5(data).hexdigest()
        if md5_hash in KNOWN_SIGNATURES:
            return KNOWN_SIGNATURES[md5_hash]

        sha256_hash = hashlib.sha256(data).hexdigest()
        if sha256_hash in KNOWN_SIGNATURES:
            return KNOWN_SIGNATURES[sha256_hash]

        return None

def run_standalone_daemon(host: str = "127.0.0.1", port: int = 3310):
    daemon = ClamDaemon(host=host, port=port)
    try:
        daemon.start()
    except (KeyboardInterrupt, SystemExit):
        daemon.stop()
    except Exception as e:
        print(f"[ClamAV Dev Emulator Error] {e}", flush=True)
        daemon.stop()

if __name__ == "__main__":
    run_standalone_daemon()

