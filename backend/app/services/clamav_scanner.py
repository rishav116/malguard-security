import socket
import select
import struct
import time
import subprocess
import shutil
from typing import Optional
from app.config import settings
from app.models.schemas import ClamAVResult
from app.core.logging import logger

class ClamAVScanner:
    """
    Isolated ClamAV scanning integration.
    Attempts clamd daemon communication via TCP socket first;
    falls back to clamscan CLI binary;
    returns explicit 'unavailable' status if ClamAV is not installed or offline.
    """
    
    def __init__(self, host: str = settings.CLAMAV_HOST, port: int = settings.CLAMAV_PORT, timeout: float = settings.CLAMAV_TIMEOUT_SEC):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _connect_socket(self, timeout: float = 1.5) -> Optional[socket.socket]:
        """
        Non-blocking socket connection with configurable timeout (default 1.5s).
        Avoids connection hangs while allowing sufficient time under CPU load.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            err = s.connect_ex((self.host, self.port))
            if err == 0:
                s.setblocking(True)
                s.settimeout(self.timeout)
                return s
            _, writable, exceptional = select.select([], [s], [s], timeout)
            if writable and not exceptional:
                sock_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if sock_err == 0:
                    s.setblocking(True)
                    s.settimeout(self.timeout)
                    return s
            s.close()
            return None
        except Exception:
            return None
        
    def ping_daemon(self, timeout: float = 1.0) -> bool:
        """Pings clamd daemon to test TCP connectivity."""
        s = self._connect_socket(timeout=timeout)
        if not s:
            return False
        try:
            with s:
                s.settimeout(timeout)
                s.sendall(b"zPING\x00")
                response = s.recv(1024)
                return b"PONG" in response
        except Exception:
            return False

    def get_daemon_version(self, timeout: float = 1.5) -> Optional[str]:
        """Queries clamd daemon for its version string via zVERSION."""
        s = self._connect_socket(timeout=timeout)
        if not s:
            return None
        try:
            with s:
                s.settimeout(timeout)
                s.sendall(b"zVERSION\x00")
                raw = s.recv(1024).decode("utf-8", errors="ignore").strip().rstrip("\x00")
                return raw if raw else None
        except Exception:
            return None

    def verify_daemon_engine(self, timeout: float = 1.5) -> tuple[bool, bool, str]:
        """
        Reliably inspects and validates the connected ClamAV daemon using a single connection.
        Returns:
            (is_online: bool, is_official: bool, version_info: str)
            - is_online: True if socket connects and responds to ping or version.
            - is_official: True ONLY if version string confirms official ClamAV with database signatures.
            - version_info: Version description or error detail.
        """
        s = self._connect_socket(timeout=timeout)
        if not s:
            return False, False, "ClamAV daemon offline / unreachable on 127.0.0.1:3310"
        try:
            with s:
                s.settimeout(timeout)
                s.sendall(b"zVERSION\x00")
                raw = s.recv(1024).decode("utf-8", errors="ignore").strip().rstrip("\x00")
                if raw:
                    ver_lower = raw.lower()
                    if "emulator" in ver_lower or "dev-only" in ver_lower:
                        return True, False, raw
                    if raw.startswith("ClamAV ") and "/" in raw:
                        return True, True, raw
                    return True, False, f"Unverified daemon ({raw})"
                # If zVERSION returned empty, try ping
                s.sendall(b"zPING\x00")
                resp = s.recv(1024)
                if b"PONG" in resp:
                    return True, False, "ClamAV daemon responding (VERSION unverified)"
                return False, False, "ClamAV daemon unresponsive"
        except Exception as e:
            return False, False, f"ClamAV communication error: {str(e)}"

    def is_starting(self) -> bool:
        """Checks if clamd daemon is actively initializing signatures."""
        import os, tempfile
        tmp_dir = tempfile.gettempdir()
        return (
            os.path.exists("/var/run/clamav/clamd.starting")
            or os.path.exists("/tmp/clamd.starting")
            or os.path.exists(os.path.join(tmp_dir, "clamd.starting"))
        )

    def is_failed(self) -> tuple[bool, str]:
        """Checks if clamd daemon encountered a startup failure or crash."""
        import os, tempfile
        tmp_dir = tempfile.gettempdir()
        for path in ["/var/run/clamav/clamd.failed", "/tmp/clamd.failed", os.path.join(tmp_dir, "clamd.failed")]:
            if os.path.exists(path):
                return True, "Process exited unexpectedly during startup"
        for path in ["/var/run/clamav/clamd.timeout", "/tmp/clamd.timeout", os.path.join(tmp_dir, "clamd.timeout")]:
            if os.path.exists(path):
                return True, "Startup timed out (>60s)"
        return False, ""

    def scan_stream(self, data: bytes) -> ClamAVResult:
        """Streams raw bytes to clamd via zINSTREAM protocol."""
        start_time = time.perf_counter()
        s = self._connect_socket(timeout=0.5)
        if not s:
            logger.debug("clamd stream connection failed (daemon offline or unreachable)")
            return self._scan_with_cli_or_unavailable(data, start_time)

        try:
            with s:
                s.sendall(b"zINSTREAM\x00")
                
                # Stream in chunks (chunk format: 4-byte big-endian length + chunk data)
                chunk_size = 8192
                for i in range(0, len(data), chunk_size):
                    chunk = data[i : i + chunk_size]
                    s.sendall(struct.pack(">I", len(chunk)) + chunk)
                
                # Send zero-length chunk to indicate end of stream
                s.sendall(struct.pack(">I", 0))
                
                response = s.recv(4096).decode("utf-8", errors="ignore").strip()
                scan_ms = round((time.perf_counter() - start_time) * 1000, 2)
                
                is_online, is_official, version_str = self.verify_daemon_engine(timeout=0.3)
                is_dev = not is_official

                # Format: "stream: OK" or "stream: <SignatureName> FOUND"
                if "OK" in response:
                    msg = (
                        "ClamAV test scan completed: No test signatures detected. (Dev-only test daemon; not production ClamAV)."
                        if is_dev else
                        f"Official ClamAV scan completed: No known malware signatures detected ({version_str})."
                    )
                    return ClamAVResult(
                        status="clean",
                        available=True,
                        matched=False,
                        is_emulator=is_dev,
                        signature_name=None,
                        scan_time_ms=scan_ms,
                        message=msg
                    )
                elif "FOUND" in response:
                    # Parse signature name
                    parts = response.split("FOUND")[0].replace("stream:", "").strip()
                    sig_name = parts if parts else "Generic.Malware.Signature"
                    msg = (
                        f"Signature match (Dev-only test daemon): {sig_name}"
                        if is_dev else
                        f"Official ClamAV signature match detected: {sig_name}"
                    )
                    return ClamAVResult(
                        status="infected",
                        available=True,
                        matched=True,
                        is_emulator=is_dev,
                        signature_name=sig_name,
                        scan_time_ms=scan_ms,
                        message=msg
                    )
                else:
                    return ClamAVResult(
                        status="error",
                        available=True,
                        matched=False,
                        is_emulator=is_dev,
                        scan_time_ms=scan_ms,
                        message=f"Unexpected response from ClamAV daemon: {response}"
                    )
        except Exception as e:
            logger.debug(f"clamd stream connection failed: {e}")
            return self._scan_with_cli_or_unavailable(data, start_time)

    def _scan_with_cli_or_unavailable(self, data: bytes, start_time: float) -> ClamAVResult:
        """Fallback to clamscan binary if available on path."""
        clamscan_path = shutil.which(settings.CLAMAV_CLI_PATH)
        if not clamscan_path:
            return ClamAVResult(
                status="unavailable",
                available=False,
                matched=False,
                signature_name=None,
                scan_time_ms=None,
                message=f"ClamAV daemon (clamd on {self.host}:{self.port}) and clamscan CLI binary are unavailable."
            )
            
        # If clamscan exists, scan via stdin
        try:
            proc = subprocess.run(
                [clamscan_path, "-"],
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout * 2
            )
            scan_ms = round((time.perf_counter() - start_time) * 1000, 2)
            stdout = proc.stdout.decode("utf-8", errors="ignore")
            
            # Return code 0 = clean, 1 = infected
            if proc.returncode == 0:
                return ClamAVResult(
                    status="clean",
                    available=True,
                    matched=False,
                    scan_time_ms=scan_ms,
                    message="ClamAV CLI scan completed: No signatures matched."
                )
            elif proc.returncode == 1:
                sig_name = "Win.Malware.ClamScanMatch"
                for line in stdout.splitlines():
                    if "FOUND" in line:
                        sig_name = line.split("FOUND")[0].replace("stdin:", "").strip()
                return ClamAVResult(
                    status="infected",
                    available=True,
                    matched=True,
                    signature_name=sig_name,
                    scan_time_ms=scan_ms,
                    message=f"ClamAV signature match detected: {sig_name}"
                )
            else:
                return ClamAVResult(
                    status="error",
                    available=True,
                    matched=False,
                    scan_time_ms=scan_ms,
                    message=f"ClamAV CLI exited with code {proc.returncode}"
                )
        except Exception as e:
            logger.warning(f"ClamAV CLI execution failed: {e}")
            return ClamAVResult(
                status="unavailable",
                available=False,
                matched=False,
                message=f"ClamAV scanning failed: {str(e)}"
            )

    @staticmethod
    def is_starting() -> bool:
        """Returns True if the clamd daemon is currently in the process of starting."""
        import os
        return os.path.exists("/var/run/clamav/clamd.starting") or os.path.exists("/tmp/clamd.starting")

    @staticmethod
    def is_failed() -> bool:
        """Returns True if the clamd daemon failed to launch or exited abnormally."""
        import os
        return os.path.exists("/var/run/clamav/clamd.failed") or os.path.exists("/tmp/clamd.failed")

clamav_service = ClamAVScanner()
