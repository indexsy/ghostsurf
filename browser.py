#!/usr/bin/env python3
"""
GhostSurf - Privacy Browser with Multi-Profile, Proxy Support & API Access
Built for managing multiple Reddit accounts with full session isolation.
"""

import sys
import os
import json
import hashlib
import threading
import signal
import socket
import select
import base64
import queue
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from functools import partial

from PyQt6.QtCore import (
    Qt, QUrl, QByteArray, pyqtSignal, QObject, QTimer, pyqtSlot, QSize
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QToolBar, QLineEdit, QPushButton, QLabel,
    QComboBox, QDialog, QFormLayout, QDialogButtonBox,
    QMessageBox, QMenu, QCheckBox, QSpinBox, QTextEdit,
    QStatusBar, QSplitter, QListWidget, QListWidgetItem,
    QGroupBox, QStyle, QSizePolicy, QStackedWidget
)
from PyQt6.QtGui import (
    QAction, QIcon, QColor, QPalette, QFont, QKeySequence, QShortcut
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings,
    QWebEngineScript
)
# QNetworkProxy not used — Chromium ignores it; we use a local TCP relay instead

# ─── Constants ───────────────────────────────────────────────────────────────

APP_NAME = "GhostSurf"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).parent
PROFILES_DIR = BASE_DIR / "profiles"
CONFIG_FILE = BASE_DIR / "config.json"
API_DEFAULT_PORT = 9378

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

PRIVACY_JS = """
// Block WebRTC IP leak
if (window.RTCPeerConnection) {
    window.RTCPeerConnection = undefined;
}
if (window.webkitRTCPeerConnection) {
    window.webkitRTCPeerConnection = undefined;
}
if (navigator.mediaDevices) {
    navigator.mediaDevices.getUserMedia = undefined;
}

// Spoof canvas fingerprint — covers toDataURL, toBlob, and getImageData
(function() {
    function addNoise(imageData) {
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] ^= 1;
            imageData.data[i+1] ^= 1;
        }
    }

    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const id = ctx.getImageData(0, 0, this.width, this.height);
            addNoise(id);
            ctx.putImageData(id, 0, 0);
        }
        return origToDataURL.apply(this, arguments);
    };

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const id = ctx.getImageData(0, 0, this.width, this.height);
            addNoise(id);
            ctx.putImageData(id, 0, 0);
        }
        return origToBlob.apply(this, arguments);
    };

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
        const id = origGetImageData.apply(this, arguments);
        addNoise(id);
        return id;
    };
})();

// Spoof WebGL renderer
const getParam = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(param) {
    if (param === 37445) return 'Intel Inc.';
    if (param === 37446) return 'Intel Iris OpenGL Engine';
    return getParam.apply(this, arguments);
};

// Reduce navigator fingerprint surface
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
Object.defineProperty(navigator, 'plugins', { get: () => [] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });

// Block battery API
if (navigator.getBattery) {
    navigator.getBattery = undefined;
}

// Enforce Do Not Track
Object.defineProperty(navigator, 'doNotTrack', { get: () => '1' });

// Also spoof WebGL2
if (typeof WebGL2RenderingContext !== 'undefined') {
    const getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Intel Inc.';
        if (param === 37446) return 'Intel Iris OpenGL Engine';
        return getParam2.apply(this, arguments);
    };
}
"""

# ─── Dark Theme ──────────────────────────────────────────────────────────────

DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #1a1a2e;
    color: #e0e0e0;
}
QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Helvetica Neue', 'Segoe UI', sans-serif;
    font-size: 13px;
}
QToolBar {
    background-color: #16213e;
    border: none;
    padding: 4px;
    spacing: 4px;
}
QTabWidget::pane {
    border: 1px solid #0f3460;
    background: #1a1a2e;
}
QTabBar::tab {
    background: #16213e;
    color: #a0a0a0;
    padding: 8px 16px;
    border: 1px solid #0f3460;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
    min-width: 120px;
}
QTabBar::tab:selected {
    background: #1a1a2e;
    color: #e94560;
    border-bottom: 2px solid #e94560;
}
QTabBar::tab:hover {
    background: #0f3460;
    color: #ffffff;
}
QLineEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 16px;
    padding: 6px 14px;
    selection-background-color: #e94560;
}
QLineEdit:focus {
    border: 1px solid #e94560;
}
QPushButton {
    background-color: #0f3460;
    color: #e0e0e0;
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #e94560;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #c73e54;
}
QComboBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 6px;
    padding: 5px 10px;
    min-width: 150px;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    selection-background-color: #e94560;
}
QMenu {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 4px;
}
QMenu::item:selected {
    background-color: #e94560;
    border-radius: 4px;
}
QLabel {
    color: #e0e0e0;
}
QStatusBar {
    background-color: #16213e;
    color: #a0a0a0;
    border-top: 1px solid #0f3460;
}
QGroupBox {
    border: 1px solid #0f3460;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
    color: #e94560;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QCheckBox {
    color: #e0e0e0;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #0f3460;
    background: #16213e;
}
QCheckBox::indicator:checked {
    background: #e94560;
    border-color: #e94560;
}
QSpinBox {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 6px;
    padding: 4px 8px;
}
QListWidget {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 4px;
}
QListWidget::item {
    padding: 8px;
    border-radius: 4px;
}
QListWidget::item:selected {
    background-color: #0f3460;
    color: #e94560;
}
QListWidget::item:hover {
    background-color: #0f3460;
}
QScrollBar:vertical {
    background: #1a1a2e;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #0f3460;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QTextEdit {
    background-color: #16213e;
    color: #e0e0e0;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 8px;
}
"""

LOCAL_PROXY_PORT = 18899  # Local relay port that Chromium connects to


# ─── Local Proxy Relay ──────────────────────────────────────────────────────

class ProxyRelay:
    """
    A local TCP relay that Chromium's --proxy-server points to.
    Forwards all traffic to the currently configured upstream proxy.
    When upstream is None, connects directly (no proxy).

    This exists because QtWebEngine/Chromium ignores QNetworkProxy entirely.
    Chromium only reads --proxy-server at startup, so we give it a fixed
    local address and dynamically swap the upstream target.
    """

    def __init__(self, listen_port):
        self.listen_port = listen_port
        self.upstream_host = None
        self.upstream_port = None
        self.upstream_type = "http"  # "http" or "socks5"
        self.upstream_username = None
        self.upstream_password = None
        self._server_socket = None
        self._running = False
        self._lock = threading.Lock()

    def set_upstream(self, host, port, proxy_type="http", username=None, password=None):
        with self._lock:
            self.upstream_host = host if host else None
            self.upstream_port = port if port else None
            self.upstream_type = proxy_type
            self.upstream_username = username if username else None
            self.upstream_password = password if password else None
            mode = f"{proxy_type}://{host}:{port}" if host else "DIRECT"
            auth = f" (user={username[:20]}...)" if username else ""
            print(f"[ProxyRelay] Upstream set to {mode}{auth}")

    def clear_upstream(self):
        with self._lock:
            self.upstream_host = None
            self.upstream_port = None
            self.upstream_username = None
            self.upstream_password = None
            print("[ProxyRelay] Upstream cleared (DIRECT)")

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("127.0.0.1", self.listen_port))
        self._server_socket.listen(64)
        self._server_socket.settimeout(1.0)
        self._running = True
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        print(f"[ProxyRelay] Listening on 127.0.0.1:{self.listen_port}")

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_client, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client_sock):
        """Handle an incoming connection from Chromium.

        Chromium sends an HTTP CONNECT request for HTTPS, or a full
        HTTP request for plain HTTP. We read the first request to
        determine the target, then either tunnel (CONNECT) or forward.
        """
        try:
            client_sock.settimeout(30)
            # Read the initial request line
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = client_sock.recv(4096)
                if not chunk:
                    client_sock.close()
                    return
                data += chunk

            first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split()
            if len(parts) < 2:
                client_sock.close()
                return

            method = parts[0].upper()

            with self._lock:
                has_upstream = self.upstream_host and self.upstream_port

            if has_upstream:
                self._forward_via_upstream(client_sock, data, method)
            else:
                self._forward_direct(client_sock, data, method, parts)

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _forward_via_upstream(self, client_sock, data, method):
        """Forward traffic through the upstream proxy (HTTP or SOCKS5)."""
        with self._lock:
            host = self.upstream_host
            port = self.upstream_port
            ptype = self.upstream_type
            username = self.upstream_username
            password = self.upstream_password

        if ptype == "socks5":
            self._forward_via_socks5(client_sock, data, method, host, port)
        else:
            self._forward_via_http_proxy(client_sock, data, method, host, port, username, password)

    def _forward_via_http_proxy(self, client_sock, data, method, host, port, username=None, password=None):
        """Forward through an HTTP proxy, injecting Proxy-Authorization if needed."""
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except Exception:
            if method == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Inject Proxy-Authorization header if credentials are provided
        if username and password:
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            auth_header = f"Proxy-Authorization: Basic {creds}\r\n".encode()
            # Insert auth header before the final \r\n\r\n
            header_end = data.index(b"\r\n\r\n")
            data = data[:header_end] + b"\r\n" + auth_header.rstrip(b"\r\n") + data[header_end:]

        upstream.sendall(data)

        if method == "CONNECT":
            resp = b""
            while b"\r\n\r\n" not in resp and len(resp) < 65536:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                resp += chunk
            client_sock.sendall(resp)
            if b"200" not in resp.split(b"\r\n")[0]:
                upstream.close()
                return

        self._bridge(client_sock, upstream)

    def _forward_via_socks5(self, client_sock, data, method, socks_host, socks_port):
        """Forward through a SOCKS5 proxy with proper handshake."""
        # Parse the target from the HTTP request
        first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts = first_line.split()

        if method == "CONNECT":
            target = parts[1]
            if ":" in target:
                dest_host, dest_port = target.rsplit(":", 1)
                dest_port = int(dest_port)
            else:
                dest_host, dest_port = target, 443
        else:
            url = parts[1]
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            dest_host = parsed.hostname
            dest_port = parsed.port or 80

        try:
            upstream = socket.create_connection((socks_host, socks_port), timeout=15)
        except Exception:
            if method == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # SOCKS5 handshake — no auth
        upstream.sendall(b"\x05\x01\x00")  # version 5, 1 method, no auth
        resp = upstream.recv(2)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            # Try with username/password auth method too
            upstream.close()
            try:
                upstream = socket.create_connection((socks_host, socks_port), timeout=15)
            except Exception:
                if method == "CONNECT":
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            upstream.sendall(b"\x05\x02\x00\x02")  # no auth + user/pass
            resp = upstream.recv(2)
            if len(resp) < 2 or resp[0] != 0x05:
                upstream.close()
                if method == "CONNECT":
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

        # SOCKS5 CONNECT request
        # Use domain name addressing (type 0x03)
        dest_bytes = dest_host.encode("utf-8")
        socks_req = (
            b"\x05\x01\x00\x03"
            + bytes([len(dest_bytes)])
            + dest_bytes
            + dest_port.to_bytes(2, "big")
        )
        upstream.sendall(socks_req)

        # Read SOCKS5 response (min 10 bytes for IPv4)
        resp = b""
        while len(resp) < 4:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            resp += chunk

        if len(resp) < 4 or resp[1] != 0x00:
            # SOCKS5 connect failed
            upstream.close()
            if method == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Drain remaining SOCKS5 response bytes based on address type
        atype = resp[3]
        if atype == 0x01:  # IPv4
            needed = 10
        elif atype == 0x03:  # Domain
            needed = 4 + 1 + resp[4] + 2 if len(resp) > 4 else 10
        elif atype == 0x04:  # IPv6
            needed = 22
        else:
            needed = 10
        while len(resp) < needed:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            resp += chunk

        if method == "CONNECT":
            # Tell Chromium the tunnel is established
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(client_sock, upstream)
        else:
            # For plain HTTP, rewrite the request to relative path and send through
            parsed = urlparse(parts[1] if parts[1].startswith("http") else f"http://{parts[1]}")
            rel_path = parsed.path or "/"
            if parsed.query:
                rel_path += f"?{parsed.query}"
            first_line_end = data.index(b"\r\n")
            new_first_line = f"{method} {rel_path} HTTP/1.1".encode()
            data = new_first_line + data[first_line_end:]
            upstream.sendall(data)
            self._bridge(client_sock, upstream)

    def _forward_direct(self, client_sock, data, method, parts):
        """Connect directly to the target (no upstream proxy)."""
        if method == "CONNECT":
            # CONNECT host:port
            target = parts[1]
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = target, 443

            try:
                remote = socket.create_connection((host, port), timeout=15)
            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(client_sock, remote)
        else:
            # Regular HTTP request - parse host from URL or Host header
            url = parts[1]
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            host = parsed.hostname
            port = parsed.port or 80

            try:
                remote = socket.create_connection((host, port), timeout=15)
            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            # Rewrite request line to relative path for direct connection
            rel_path = parsed.path or "/"
            if parsed.query:
                rel_path += f"?{parsed.query}"
            first_line_end = data.index(b"\r\n")
            new_first_line = f"{method} {rel_path} HTTP/1.1".encode()
            data = new_first_line + data[first_line_end:]

            remote.sendall(data)
            self._bridge(client_sock, remote)

    def _bridge(self, sock1, sock2):
        """Bidirectional data bridge between two sockets."""
        sockets = [sock1, sock2]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored:
                    break
                if not readable:
                    break  # timeout
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    other = sock2 if s is sock1 else sock1
                    other.sendall(data)
        except Exception:
            pass
        finally:
            try:
                sock1.close()
            except Exception:
                pass
            try:
                sock2.close()
            except Exception:
                pass


# ─── Profile Manager ────────────────────────────────────────────────────────

class ProfileManager:
    """Manages browser profiles with isolated storage."""

    def __init__(self):
        PROFILES_DIR.mkdir(exist_ok=True)
        self.profiles = {}
        self._load_config()

    def _load_config(self):
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                self.profiles = data.get("profiles", {})
        else:
            # Create default profile
            self.profiles = {
                "default": {
                    "name": "Default",
                    "color": "#e94560",
                    "proxy": {"enabled": False, "type": "http", "host": "", "port": 0, "username": "", "password": ""},
                    "user_agent": DEFAULT_USER_AGENTS[0],
                    "homepage": "https://www.reddit.com",
                    "privacy": {
                        "block_webrtc": True,
                        "spoof_canvas": True,
                        "spoof_webgl": True,
                        "block_third_party_cookies": True,
                        "do_not_track": True,
                    },
                    "notes": "",
                }
            }
            self._save_config()

    def _save_config(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump({"profiles": self.profiles, "version": APP_VERSION}, f, indent=2)

    def get_profile(self, profile_id):
        return self.profiles.get(profile_id)

    def list_profiles(self):
        return dict(self.profiles)

    def create_profile(self, profile_id, config):
        self.profiles[profile_id] = config
        profile_dir = PROFILES_DIR / profile_id
        profile_dir.mkdir(exist_ok=True)
        self._save_config()

    def update_profile(self, profile_id, config):
        if profile_id in self.profiles:
            self.profiles[profile_id].update(config)
            self._save_config()

    def delete_profile(self, profile_id):
        if profile_id in self.profiles and profile_id != "default":
            del self.profiles[profile_id]
            self._save_config()
            return True
        return False

    def get_storage_path(self, profile_id):
        path = PROFILES_DIR / profile_id
        path.mkdir(exist_ok=True)
        return str(path)


# ─── Profile Edit Dialog ────────────────────────────────────────────────────

class ProfileDialog(QDialog):
    """Dialog for creating/editing a profile."""

    def __init__(self, parent=None, profile_data=None, profile_id=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Profile" if profile_data else "New Profile")
        self.setMinimumWidth(480)
        self.profile_data = profile_data or {}

        layout = QVBoxLayout(self)

        # Basic info
        basic_group = QGroupBox("Profile")
        basic_layout = QFormLayout()

        self.name_edit = QLineEdit(self.profile_data.get("name", ""))
        self.name_edit.setPlaceholderText("e.g. Reddit Alt 1")
        basic_layout.addRow("Name:", self.name_edit)

        self.id_edit = QLineEdit(profile_id or "")
        self.id_edit.setPlaceholderText("e.g. reddit-alt1 (lowercase, no spaces)")
        if profile_id:
            self.id_edit.setReadOnly(True)
            self.id_edit.setStyleSheet("color: #666;")
        basic_layout.addRow("ID:", self.id_edit)

        self.color_edit = QLineEdit(self.profile_data.get("color", "#e94560"))
        self.color_edit.setPlaceholderText("#hex color")
        basic_layout.addRow("Color:", self.color_edit)

        self.homepage_edit = QLineEdit(self.profile_data.get("homepage", "https://www.reddit.com"))
        basic_layout.addRow("Homepage:", self.homepage_edit)

        self.notes_edit = QLineEdit(self.profile_data.get("notes", ""))
        self.notes_edit.setPlaceholderText("Optional notes (e.g. u/myusername)")
        basic_layout.addRow("Notes:", self.notes_edit)

        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)

        # User Agent
        ua_group = QGroupBox("Identity")
        ua_layout = QFormLayout()

        self.ua_combo = QComboBox()
        self.ua_combo.setEditable(True)
        for ua in DEFAULT_USER_AGENTS:
            label = "Chrome/Mac" if "Chrome" in ua and "Mac" in ua else \
                    "Safari/Mac" if "Safari" in ua and "Version" in ua else \
                    "Firefox/Win" if "Firefox" in ua else \
                    "Chrome/Linux"
            self.ua_combo.addItem(f"{label}: {ua[:60]}...", ua)
        current_ua = self.profile_data.get("user_agent", DEFAULT_USER_AGENTS[0])
        idx = self.ua_combo.findData(current_ua)
        if idx >= 0:
            self.ua_combo.setCurrentIndex(idx)
        else:
            self.ua_combo.setEditText(current_ua)
        ua_layout.addRow("User Agent:", self.ua_combo)
        ua_group.setLayout(ua_layout)
        layout.addWidget(ua_group)

        # Proxy
        proxy_group = QGroupBox("Proxy")
        proxy_layout = QFormLayout()
        proxy_data = self.profile_data.get("proxy", {})

        self.proxy_enabled = QCheckBox("Enable Proxy")
        self.proxy_enabled.setChecked(proxy_data.get("enabled", False))
        proxy_layout.addRow(self.proxy_enabled)

        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["http", "socks5"])
        self.proxy_type.setCurrentText(proxy_data.get("type", "http"))
        proxy_layout.addRow("Type:", self.proxy_type)

        self.proxy_host = QLineEdit(proxy_data.get("host", ""))
        self.proxy_host.setPlaceholderText("127.0.0.1")
        proxy_layout.addRow("Host:", self.proxy_host)

        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(0, 65535)
        self.proxy_port.setValue(proxy_data.get("port", 0))
        proxy_layout.addRow("Port:", self.proxy_port)

        self.proxy_user = QLineEdit(proxy_data.get("username", ""))
        self.proxy_user.setPlaceholderText("Optional")
        proxy_layout.addRow("Username:", self.proxy_user)

        self.proxy_pass = QLineEdit(proxy_data.get("password", ""))
        self.proxy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_pass.setPlaceholderText("Optional")
        proxy_layout.addRow("Password:", self.proxy_pass)

        proxy_group.setLayout(proxy_layout)
        layout.addWidget(proxy_group)

        # Privacy
        privacy_group = QGroupBox("Privacy")
        privacy_layout = QVBoxLayout()
        privacy_data = self.profile_data.get("privacy", {})

        self.block_webrtc = QCheckBox("Block WebRTC (prevents IP leak)")
        self.block_webrtc.setChecked(privacy_data.get("block_webrtc", True))
        privacy_layout.addWidget(self.block_webrtc)

        self.spoof_canvas = QCheckBox("Spoof Canvas fingerprint")
        self.spoof_canvas.setChecked(privacy_data.get("spoof_canvas", True))
        privacy_layout.addWidget(self.spoof_canvas)

        self.spoof_webgl = QCheckBox("Spoof WebGL renderer")
        self.spoof_webgl.setChecked(privacy_data.get("spoof_webgl", True))
        privacy_layout.addWidget(self.spoof_webgl)

        self.block_3p_cookies = QCheckBox("Block third-party cookies")
        self.block_3p_cookies.setChecked(privacy_data.get("block_third_party_cookies", True))
        privacy_layout.addWidget(self.block_3p_cookies)

        self.dnt = QCheckBox("Send Do Not Track header")
        self.dnt.setChecked(privacy_data.get("do_not_track", True))
        privacy_layout.addWidget(self.dnt)

        privacy_group.setLayout(privacy_layout)
        layout.addWidget(privacy_group)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_data(self):
        ua = self.ua_combo.currentData() or self.ua_combo.currentText()
        return {
            "id": self.id_edit.text().strip().lower().replace(" ", "-"),
            "config": {
                "name": self.name_edit.text().strip() or "Unnamed",
                "color": self.color_edit.text().strip(),
                "homepage": self.homepage_edit.text().strip() or "https://www.reddit.com",
                "user_agent": ua,
                "notes": self.notes_edit.text().strip(),
                "proxy": {
                    "enabled": self.proxy_enabled.isChecked(),
                    "type": self.proxy_type.currentText(),
                    "host": self.proxy_host.text().strip(),
                    "port": self.proxy_port.value(),
                    "username": self.proxy_user.text().strip(),
                    "password": self.proxy_pass.text().strip(),
                },
                "privacy": {
                    "block_webrtc": self.block_webrtc.isChecked(),
                    "spoof_canvas": self.spoof_canvas.isChecked(),
                    "spoof_webgl": self.spoof_webgl.isChecked(),
                    "block_third_party_cookies": self.block_3p_cookies.isChecked(),
                    "do_not_track": self.dnt.isChecked(),
                },
            }
        }


# ─── Web Engine Page with Privacy ───────────────────────────────────────────

class PrivacyWebPage(QWebEnginePage):
    """Custom web page with privacy script injection."""

    def __init__(self, profile_obj, privacy_config, user_agent, parent=None):
        super().__init__(profile_obj, parent)
        self._user_agent = user_agent
        self._privacy = privacy_config

        # Inject privacy JS
        if any(self._privacy.get(k) for k in ["block_webrtc", "spoof_canvas", "spoof_webgl"]):
            script = QWebEngineScript()
            script.setName("ghostsurf_privacy")
            script.setSourceCode(PRIVACY_JS)
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            script.setRunsOnSubFrames(True)
            self.scripts().insert(script)

    def userAgentForUrl(self, url):
        return self._user_agent


# ─── Browser Tab ─────────────────────────────────────────────────────────────

class BrowserTab(QWidget):
    """A single browser tab with its own web view."""

    title_changed = pyqtSignal(int, str)
    url_changed = pyqtSignal(int, str)

    def __init__(self, tab_index, qt_profile, privacy_config, user_agent, start_url=None, parent=None):
        super().__init__(parent)
        self.tab_index = tab_index

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        page = PrivacyWebPage(qt_profile, privacy_config, user_agent, self.web_view)
        self.web_view.setPage(page)

        # Configure settings
        settings = self.web_view.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)

        self.web_view.titleChanged.connect(lambda t: self.title_changed.emit(self.tab_index, t))
        self.web_view.urlChanged.connect(lambda u: self.url_changed.emit(self.tab_index, u.toString()))

        layout.addWidget(self.web_view)

        if start_url:
            self.web_view.load(QUrl(start_url))

    def navigate(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.web_view.load(QUrl(url))

    def current_url(self):
        return self.web_view.url().toString()

    def current_title(self):
        return self.web_view.title()


# ─── Profile Browser Window ─────────────────────────────────────────────────

class ProfileWindow(QMainWindow):
    """A browser window bound to a single profile. Each window has its own
    proxy relay so there is zero cross-profile leakage."""

    window_closed = pyqtSignal(str)  # emits profile_id on close
    _js_execute_signal = pyqtSignal(str, int, int)   # code, tab_index, queue_id
    _navigate_signal = pyqtSignal(str, int, int)     # url, tab_index, queue_id
    _new_tab_signal = pyqtSignal(str, int)           # url, queue_id

    def __init__(self, profile_id, profile_config, profile_manager, relay_port, relay=None):
        super().__init__()
        self.profile_id = profile_id
        self.profile_config = profile_config
        self.profile_manager = profile_manager
        self.qt_profile = None
        self.tabs = []

        self._pending_results = {}  # queue_id -> queue.Queue
        self._next_queue_id = 0
        self._queue_lock = threading.Lock()

        # Use provided relay or create a new one
        if relay is not None:
            self.proxy_relay = relay
        else:
            self.proxy_relay = ProxyRelay(relay_port)
            self.proxy_relay.start()
        self._apply_proxy(profile_config.get("proxy", {}))

        # Connect API signals for thread-safe calls
        self._js_execute_signal.connect(self._on_js_execute)
        self._navigate_signal.connect(self._on_navigate)
        self._new_tab_signal.connect(self._on_new_tab)

        self._setup_ui()
        self._setup_shortcuts()
        self._new_tab()

    def _setup_ui(self):
        name = self.profile_config.get("name", self.profile_id)
        color = self.profile_config.get("color", "#e94560")
        notes = self.profile_config.get("notes", "")
        title = f"{APP_NAME} — {name}"
        if notes:
            title += f" ({notes})"
        self.setWindowTitle(title)
        self.resize(1400, 900)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Toolbar
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        self.addToolBar(toolbar)

        # Profile badge
        badge = QLabel(f"  {name}  ")
        badge.setStyleSheet(f"background: {color}; color: #fff; border-radius: 4px; padding: 4px 8px; font-weight: bold;")
        toolbar.addWidget(badge)
        toolbar.addSeparator()

        # Navigation
        back_btn = QPushButton("<")
        back_btn.setFixedSize(32, 32)
        back_btn.clicked.connect(self._go_back)
        toolbar.addWidget(back_btn)

        fwd_btn = QPushButton(">")
        fwd_btn.setFixedSize(32, 32)
        fwd_btn.clicked.connect(self._go_forward)
        toolbar.addWidget(fwd_btn)

        reload_btn = QPushButton("R")
        reload_btn.setFixedSize(32, 32)
        reload_btn.clicked.connect(self._reload)
        toolbar.addWidget(reload_btn)

        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or search...")
        self.url_bar.returnPressed.connect(self._navigate)
        toolbar.addWidget(self.url_bar)

        new_tab_btn = QPushButton("+")
        new_tab_btn.setFixedSize(32, 32)
        new_tab_btn.setToolTip("New Tab")
        new_tab_btn.clicked.connect(self._new_tab)
        toolbar.addWidget(new_tab_btn)

        reddit_btn = QPushButton("Reddit")
        reddit_btn.clicked.connect(lambda: self._quick_nav("https://www.reddit.com"))
        toolbar.addWidget(reddit_btn)

        toolbar.addSeparator()

        clear_btn = QPushButton("Clear Data")
        clear_btn.clicked.connect(self._clear_profile_data)
        toolbar.addWidget(clear_btn)

        # Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        main_layout.addWidget(self.tab_widget)

        # Status bar
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        proxy = self.profile_config.get("proxy", {})
        if proxy.get("enabled"):
            proxy_label = QLabel(f"  Proxy: {proxy['type'].upper()} {proxy['host']}:{proxy['port']}  ")
            proxy_label.setStyleSheet("color: #4ecca3;")
        else:
            proxy_label = QLabel("  Proxy: DIRECT  ")
            proxy_label.setStyleSheet("color: #666;")
        status_bar.addPermanentWidget(proxy_label)

        # Color the tab bar
        self.setStyleSheet(self.styleSheet() + f"""
        QTabBar::tab:selected {{ border-bottom: 2px solid {color}; color: {color}; }}
        """)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+T"), self, self._new_tab)
        QShortcut(QKeySequence("Ctrl+W"), self, self._close_current_tab)
        QShortcut(QKeySequence("Ctrl+L"), self, lambda: self.url_bar.setFocus())
        QShortcut(QKeySequence("Ctrl+R"), self, self._reload)
        QShortcut(QKeySequence("Meta+T"), self, self._new_tab)
        QShortcut(QKeySequence("Meta+W"), self, self._close_current_tab)
        QShortcut(QKeySequence("Meta+L"), self, lambda: self.url_bar.setFocus())
        QShortcut(QKeySequence("Meta+R"), self, self._reload)

    def _get_qt_profile(self):
        if self.qt_profile is None:
            storage_path = self.profile_manager.get_storage_path(self.profile_id)
            self.qt_profile = QWebEngineProfile(self.profile_id, self)
            self.qt_profile.setPersistentStoragePath(storage_path)
            self.qt_profile.setCachePath(os.path.join(storage_path, "cache"))
            self.qt_profile.setPersistentCookiesPolicy(
                QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
            )
            ua = self.profile_config.get("user_agent", DEFAULT_USER_AGENTS[0])
            self.qt_profile.setHttpUserAgent(ua)

            privacy = self.profile_config.get("privacy", {})

            # Block third-party cookies
            if privacy.get("block_third_party_cookies"):
                self.qt_profile.cookieStore().setCookieFilter(
                    lambda request: not request.thirdParty
                )
        return self.qt_profile

    def _apply_proxy(self, proxy_config):
        if not proxy_config.get("enabled"):
            self.proxy_relay.clear_upstream()
            return
        self.proxy_relay.set_upstream(
            proxy_config.get("host", ""),
            proxy_config.get("port", 0),
            proxy_config.get("type", "http"),
            proxy_config.get("username", ""),
            proxy_config.get("password", ""),
        )

    # ── Tabs ──

    def _new_tab(self, url=None):
        qt_profile = self._get_qt_profile()
        if url is None:
            url = self.profile_config.get("homepage", "https://www.reddit.com")
        privacy = self.profile_config.get("privacy", {})
        ua = self.profile_config.get("user_agent", DEFAULT_USER_AGENTS[0])

        tab_index = self.tab_widget.count()
        tab = BrowserTab(tab_index, qt_profile, privacy, ua, url)
        tab.title_changed.connect(self._on_title_changed)
        tab.url_changed.connect(self._on_url_changed)
        self.tabs.append(tab)
        idx = self.tab_widget.addTab(tab, "Loading...")
        self.tab_widget.setCurrentIndex(idx)
        return idx

    def _close_tab(self, index):
        if self.tab_widget.count() > 1:
            widget = self.tab_widget.widget(index)
            self.tab_widget.removeTab(index)
            if widget in self.tabs:
                self.tabs.remove(widget)
            widget.deleteLater()
            for i, tab in enumerate(self.tabs):
                tab.tab_index = i

    def _close_current_tab(self):
        self._close_tab(self.tab_widget.currentIndex())

    def _on_tab_changed(self, index):
        widget = self.tab_widget.widget(index)
        if widget and hasattr(widget, 'current_url'):
            self.url_bar.setText(widget.current_url())

    def _on_title_changed(self, tab_index, title):
        for i in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(i)
            if hasattr(widget, 'tab_index') and widget.tab_index == tab_index:
                short = title[:30] + "..." if len(title) > 30 else title
                self.tab_widget.setTabText(i, short)
                break

    def _on_url_changed(self, tab_index, url):
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'tab_index') and current.tab_index == tab_index:
            self.url_bar.setText(url)

    # ── Navigation ──

    def _navigate(self):
        url = self.url_bar.text().strip()
        if not url:
            return
        if " " in url or ("." not in url and "/" not in url):
            url = f"https://duckduckgo.com/?q={url}"
        elif not url.startswith(("http://", "https://")):
            url = "https://" + url
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'navigate'):
            current.navigate(url)

    def _go_back(self):
        w = self.tab_widget.currentWidget()
        if w and hasattr(w, 'web_view'):
            w.web_view.back()

    def _go_forward(self):
        w = self.tab_widget.currentWidget()
        if w and hasattr(w, 'web_view'):
            w.web_view.forward()

    def _reload(self):
        w = self.tab_widget.currentWidget()
        if w and hasattr(w, 'web_view'):
            w.web_view.reload()

    def _quick_nav(self, url):
        w = self.tab_widget.currentWidget()
        if w and hasattr(w, 'navigate'):
            w.navigate(url)
            self.url_bar.setText(url)

    def _clear_profile_data(self):
        reply = QMessageBox.question(
            self, "Clear Profile Data",
            f"Clear all cookies, cache, and storage for this profile?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes and self.qt_profile:
            self.qt_profile.clearAllVisitedLinks()
            self.qt_profile.clearHttpCache()
            self.qt_profile.cookieStore().deleteAllCookies()
            self.statusBar().showMessage("Profile data cleared.", 3000)

    def get_tabs_info(self):
        result = []
        for i in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(i)
            if hasattr(widget, 'current_url'):
                result.append({"index": i, "url": widget.current_url(), "title": widget.current_title()})
        return result

    # ── Signal slots for thread-safe API calls ──

    def _resolve_queue(self, queue_id, data):
        with self._queue_lock:
            q = self._pending_results.pop(queue_id, None)
        if q:
            q.put(data)

    def register_queue(self, q):
        with self._queue_lock:
            qid = self._next_queue_id
            self._next_queue_id = (self._next_queue_id + 1) % 2000000000
            self._pending_results[qid] = q
        return qid

    @pyqtSlot(str, int, int)
    def _on_js_execute(self, code, tab_index, queue_id):
        idx = tab_index if tab_index >= 0 else self.tab_widget.currentIndex()
        widget = self.tab_widget.widget(idx)
        if not widget or not hasattr(widget, 'web_view'):
            self._resolve_queue(queue_id, {"error": "No tab at that index"})
            return
        page = widget.web_view.page()
        page.runJavaScript(code, 0, lambda result: self._resolve_queue(queue_id, {"result": result}))

    @pyqtSlot(str, int, int)
    def _on_navigate(self, url, tab_index, queue_id):
        idx = tab_index if tab_index >= 0 else self.tab_widget.currentIndex()
        result = self.api_navigate_tab(url, idx)
        self._resolve_queue(queue_id, result)

    @pyqtSlot(str, int)
    def _on_new_tab(self, url, queue_id):
        result = self.api_new_tab_url(url if url else None)
        self._resolve_queue(queue_id, result)

    # ── Per-profile API ──

    def start_api(self, port):
        """Start a local API server for this profile window."""
        self._api_port = port
        handler = partial(ProfileAPIHandler, self)
        try:
            self._api_server = HTTPServer(("127.0.0.1", port), handler)
            threading.Thread(target=self._api_server.serve_forever, daemon=True).start()
            print(f"[GhostSurf:{self.profile_id}] Profile API on http://127.0.0.1:{port}")
        except OSError as e:
            print(f"[GhostSurf:{self.profile_id}] Profile API failed: {e}")
            self._api_server = None

    def api_execute_js(self, code, tab_index=None, callback=None):
        """Execute JS in a tab and return the result via callback."""
        idx = tab_index if tab_index is not None else self.tab_widget.currentIndex()
        widget = self.tab_widget.widget(idx)
        if not widget or not hasattr(widget, 'web_view'):
            if callback:
                callback({"error": "No tab at that index"})
            return
        page = widget.web_view.page()
        page.runJavaScript(code, 0, lambda result: callback({"result": result}) if callback else None)

    def api_navigate_tab(self, url, tab_index=None):
        idx = tab_index if tab_index is not None and tab_index >= 0 else self.tab_widget.currentIndex()
        widget = self.tab_widget.widget(idx)
        if not widget or not hasattr(widget, 'navigate'):
            return {"error": "No tab at that index"}
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        widget.navigate(url)
        self.url_bar.setText(url)
        return {"status": "ok", "url": url, "tab": idx}

    def api_get_tabs_info(self):
        return self.get_tabs_info()

    def api_new_tab_url(self, url=None):
        idx = self._new_tab(url)
        return {"status": "ok", "tab_index": idx}

    def api_close_tab_idx(self, index):
        if self.tab_widget.count() <= 1:
            return {"error": "Cannot close last tab"}
        self._close_tab(index)
        return {"status": "ok"}

    def closeEvent(self, event):
        if hasattr(self, '_api_server') and self._api_server:
            self._api_server.shutdown()
        self.proxy_relay.stop()
        self.window_closed.emit(self.profile_id)
        super().closeEvent(event)


# ─── Launcher Window ────────────────────────────────────────────────────────

class GhostSurfLauncher(QMainWindow):
    """Launcher that opens separate browser windows per profile."""

    _open_profile_signal = pyqtSignal(str)
    _refresh_signal = pyqtSignal()
    _window_closed_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.profile_manager = ProfileManager()
        self.open_windows = {}   # profile_id -> {"proc": Popen, "api_port": int}
        self._next_relay_port = LOCAL_PROXY_PORT
        self._next_api_port = API_DEFAULT_PORT + 1  # 9379, 9380, ...
        self.api_server = None

        # Connect signals for thread-safe calls from API handler
        self._open_profile_signal.connect(self._open_profile)
        self._refresh_signal.connect(self._refresh_list)
        self._window_closed_signal.connect(self._on_window_closed)

        self._setup_ui()
        self._start_api_server()

    def _alloc_relay_port(self):
        port = self._next_relay_port
        self._next_relay_port += 1
        return port

    def _alloc_api_port(self):
        port = self._next_api_port
        self._next_api_port += 1
        return port

    def _setup_ui(self):
        self.setWindowTitle(f"{APP_NAME} — Profile Launcher")
        self.setFixedSize(500, 600)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel(f"{APP_NAME}")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #e94560;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Select a profile to open in its own isolated window")
        subtitle.setStyleSheet("color: #888; margin-bottom: 12px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        # Profile list
        self.profile_list = QListWidget()
        self.profile_list.setStyleSheet("QListWidget::item { padding: 12px; }")
        self.profile_list.itemDoubleClicked.connect(self._on_profile_double_clicked)
        self._refresh_list()
        layout.addWidget(self.profile_list)

        # Buttons
        btn_layout = QHBoxLayout()

        open_btn = QPushButton("Open Window")
        open_btn.setStyleSheet("background: #e94560; font-weight: bold; padding: 10px 20px;")
        open_btn.clicked.connect(self._open_selected)
        btn_layout.addWidget(open_btn)

        manage_btn = QPushButton("Manage")
        manage_btn.clicked.connect(self._show_profile_manager)
        btn_layout.addWidget(manage_btn)

        layout.addLayout(btn_layout)

        # Status
        self.status_label = QLabel(f"API: http://127.0.0.1:{API_DEFAULT_PORT}")
        self.status_label.setStyleSheet("color: #4ecca3; margin-top: 8px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

    def _refresh_list(self):
        self.profile_list.clear()
        for pid, pdata in self.profile_manager.list_profiles().items():
            label = f"{pdata['name']}"
            if pdata.get("notes"):
                label += f"  —  {pdata['notes']}"
            proxy = pdata.get("proxy", {})
            if proxy.get("enabled"):
                label += f"  |  {proxy['host']}:{proxy['port']}"
            if pid in self.open_windows:
                label += "  [OPEN]"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, pid)
            self.profile_list.addItem(item)

    def _on_profile_double_clicked(self, item):
        self._open_profile(item.data(Qt.ItemDataRole.UserRole))

    def _open_selected(self):
        item = self.profile_list.currentItem()
        if item:
            self._open_profile(item.data(Qt.ItemDataRole.UserRole))

    def _open_profile(self, profile_id):
        if profile_id in self.open_windows:
            # Check if process is still running
            info = self.open_windows[profile_id]
            if info["proc"].poll() is None:
                return  # still running
            else:
                del self.open_windows[profile_id]

        config = self.profile_manager.get_profile(profile_id)
        if not config:
            return

        relay_port = self._alloc_relay_port()
        api_port = self._alloc_api_port()
        import subprocess as sp
        proc = sp.Popen([
            sys.executable, __file__,
            "--profile", profile_id,
            "--relay-port", str(relay_port),
            "--api-port", str(api_port),
        ])
        self.open_windows[profile_id] = {"proc": proc, "api_port": api_port}
        self._refresh_list()

        # Monitor for exit in background thread
        def watch():
            proc.wait()
            self._window_closed_signal.emit(profile_id)
        threading.Thread(target=watch, daemon=True).start()

    def _on_window_closed(self, profile_id):
        if profile_id in self.open_windows:
            del self.open_windows[profile_id]
        self._refresh_list()

    def _show_profile_manager(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Profile Manager")
        dialog.setMinimumSize(600, 500)
        layout = QVBoxLayout(dialog)

        plist = QListWidget()
        for pid, pdata in self.profile_manager.list_profiles().items():
            label = f"{pdata['name']} [{pid}]"
            if pdata.get("notes"):
                label += f" - {pdata['notes']}"
            proxy = pdata.get("proxy", {})
            if proxy.get("enabled"):
                label += f" | Proxy: {proxy['type']}://{proxy['host']}:{proxy['port']}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, pid)
            plist.addItem(item)
        layout.addWidget(plist)

        btn_layout = QHBoxLayout()

        def add_profile():
            d = ProfileDialog(dialog)
            if d.exec() == QDialog.DialogCode.Accepted:
                data = d.get_data()
                pid = data["id"]
                if pid and pid not in self.profile_manager.profiles:
                    self.profile_manager.create_profile(pid, data["config"])
                    plist.addItem(f"{data['config']['name']} [{pid}]")
                    self._refresh_list()

        def edit_profile():
            item = plist.currentItem()
            if not item:
                return
            pid = item.data(Qt.ItemDataRole.UserRole)
            pdata = self.profile_manager.get_profile(pid)
            d = ProfileDialog(dialog, profile_data=pdata, profile_id=pid)
            if d.exec() == QDialog.DialogCode.Accepted:
                data = d.get_data()
                self.profile_manager.update_profile(pid, data["config"])
                self._refresh_list()
                dialog.accept()
                self._show_profile_manager()

        def delete_profile():
            item = plist.currentItem()
            if not item:
                return
            pid = item.data(Qt.ItemDataRole.UserRole)
            if pid == "default":
                return
            if pid in self.open_windows:
                QMessageBox.warning(dialog, "Error", "Close the window first.")
                return
            reply = QMessageBox.question(dialog, "Delete", f"Delete '{pid}'?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.profile_manager.delete_profile(pid)
                self._refresh_list()
                dialog.accept()
                self._show_profile_manager()

        add_btn = QPushButton("+ New")
        add_btn.clicked.connect(add_profile)
        btn_layout.addWidget(add_btn)
        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(edit_profile)
        btn_layout.addWidget(edit_btn)
        del_btn = QPushButton("Delete")
        del_btn.clicked.connect(delete_profile)
        btn_layout.addWidget(del_btn)
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        dialog.exec()
        self._refresh_list()

    # ── API Server ──

    def _start_api_server(self):
        handler = partial(APIHandler, self)
        try:
            self.api_server = HTTPServer(("127.0.0.1", API_DEFAULT_PORT), handler)
            threading.Thread(target=self.api_server.serve_forever, daemon=True).start()
            print(f"[GhostSurf] API server on http://127.0.0.1:{API_DEFAULT_PORT}")
        except OSError as e:
            print(f"[GhostSurf] API failed: {e}")

    def closeEvent(self, event):
        for info in list(self.open_windows.values()):
            if info["proc"].poll() is None:
                info["proc"].terminate()
        if self.api_server:
            self.api_server.shutdown()
        super().closeEvent(event)

    # ── API Methods ──

    def api_get_status(self):
        windows = {}
        for pid, info in self.open_windows.items():
            if info["proc"].poll() is None:
                windows[pid] = {"api_port": info["api_port"]}
        return {
            "app": APP_NAME, "version": APP_VERSION,
            "open_windows": windows,
            "profiles": list(self.profile_manager.profiles.keys()),
        }

    def api_list_profiles(self):
        return self.profile_manager.list_profiles()

    def api_get_tabs(self):
        # Tabs are in separate processes; return which profiles are open
        return {pid: {"status": "running", "api_port": info["api_port"]}
                for pid, info in self.open_windows.items() if info["proc"].poll() is None}

    def api_navigate(self, url, tab_index=None):
        return {"status": "ok", "note": "Navigate via profile window directly", "url": url}

    def api_new_tab(self, url=None):
        return {"status": "ok", "note": "Tabs managed per profile window"}

    def api_close_tab(self, index):
        return {"status": "ok", "note": "Tabs managed per profile window"}

    def api_switch_profile(self, profile_id):
        if profile_id not in self.profile_manager.profiles:
            return {"error": f"Profile '{profile_id}' not found"}
        self._open_profile_signal.emit(profile_id)
        return {"status": "ok", "profile": profile_id}

    def api_create_profile(self, profile_id, config):
        self.profile_manager.create_profile(profile_id, config)
        self._refresh_signal.emit()
        return {"status": "ok", "profile": profile_id}

    def api_snapshot(self, tab_index=None):
        return {
            "open_windows": list(self.open_windows.keys()),
            "tabs": self.api_get_tabs(),
        }


# ─── REST API Handler ───────────────────────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the browser control API."""

    def __init__(self, browser, *args, **kwargs):
        self.browser = browser
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return json.loads(self.rfile.read(length))
        return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        routes = {
            "": lambda: self._send_json(self.browser.api_get_status()),
            "/health": lambda: self._send_json({"status": "ok"}),
            "/status": lambda: self._send_json(self.browser.api_get_status()),
            "/profiles": lambda: self._send_json(self.browser.api_list_profiles()),
            "/tabs": lambda: self._send_json(self.browser.api_get_tabs()),
            "/snapshot": lambda: self._send_json(self.browser.api_snapshot()),
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            # Proxy GET to profile subprocess: /p/{profile_id}/{action}
            import re
            m = re.match(r'^/p/([^/]+)(/.*)?$', path)
            if m:
                profile_id = m.group(1)
                sub_path = m.group(2) or "/"
                info = self.browser.open_windows.get(profile_id)
                if not info or info["proc"].poll() is not None:
                    self._send_json({"error": f"Profile '{profile_id}' is not running"}, 404)
                    return
                api_port = info["api_port"]
                try:
                    import urllib.request
                    resp = urllib.request.urlopen(f"http://127.0.0.1:{api_port}{sub_path}", timeout=5)
                    data = json.loads(resp.read())
                    self._send_json(data)
                except Exception as e:
                    self._send_json({"error": str(e)}, 502)
            else:
                self._send_json({"error": "Not found", "available": list(routes.keys())}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        try:
            body = self._read_body()
        except Exception:
            body = {}

        if path == "/navigate":
            url = body.get("url", "")
            tab_index = body.get("tab_index")
            if not url:
                self._send_json({"error": "url is required"}, 400)
                return
            self._send_json(self.browser.api_navigate(url, tab_index))

        elif path == "/tabs":
            url = body.get("url")
            self._send_json(self.browser.api_new_tab(url))

        elif path == "/tabs/close":
            index = body.get("index", 0)
            self._send_json(self.browser.api_close_tab(index))

        elif path == "/profiles/switch":
            profile_id = body.get("profile_id", "")
            if not profile_id:
                self._send_json({"error": "profile_id is required"}, 400)
                return
            self._send_json(self.browser.api_switch_profile(profile_id))

        elif path == "/profiles":
            profile_id = body.get("id", "")
            config = body.get("config", {})
            if not profile_id:
                self._send_json({"error": "id is required"}, 400)
                return
            self._send_json(self.browser.api_create_profile(profile_id, config))

        elif path == "/snapshot":
            self._send_json(self.browser.api_snapshot())

        else:
            # Proxy to profile subprocess: /p/{profile_id}/{action}
            import re
            m = re.match(r'^/p/([^/]+)(/.*)?$', path)
            if m:
                profile_id = m.group(1)
                sub_path = m.group(2) or "/"
                info = self.browser.open_windows.get(profile_id)
                if not info or info["proc"].poll() is not None:
                    self._send_json({"error": f"Profile '{profile_id}' is not running"}, 404)
                    return
                api_port = info["api_port"]
                try:
                    import urllib.request
                    proxy_body = json.dumps(body).encode() if body else b"{}"
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{api_port}{sub_path}",
                        data=proxy_body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    resp = urllib.request.urlopen(req, timeout=20)
                    data = json.loads(resp.read())
                    self._send_json(data)
                except Exception as e:
                    self._send_json({"error": str(e)}, 502)
            else:
                self._send_json({
                    "error": "Not found",
                    "available_post": ["/navigate", "/tabs", "/tabs/close", "/profiles", "/profiles/switch", "/snapshot", "/p/{profile_id}/{execute|navigate|tabs}"]
                }, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.startswith("/profiles/"):
            profile_id = path.split("/profiles/")[1]
            if self.browser.profile_manager.delete_profile(profile_id):
                self._send_json({"status": "ok", "deleted": profile_id})
            else:
                self._send_json({"error": "Cannot delete profile"}, 400)
        else:
            self._send_json({"error": "Not found"}, 404)


# ─── Profile API Handler ─────────────────────────────────────────────────────

class ProfileAPIHandler(BaseHTTPRequestHandler):
    """HTTP API handler for an individual profile window.
    Supports JS execution, navigation, and tab management."""

    def __init__(self, window, *args, **kwargs):
        self.window = window
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return json.loads(self.rfile.read(length))
        return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/status"):
            tabs = self.window.api_get_tabs_info()
            self._send_json({
                "profile": self.window.profile_id,
                "tabs": tabs,
                "current_tab": self.window.tab_widget.currentIndex(),
            })
        elif path == "/tabs":
            self._send_json(self.window.api_get_tabs_info())
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        try:
            body = self._read_body()
        except Exception:
            body = {}

        if path == "/execute":
            code = body.get("js", "")
            tab_index = body.get("tab_index")
            if not code:
                self._send_json({"error": "js is required"}, 400)
                return
            result_q = queue.Queue()
            qid = self.window.register_queue(result_q)
            self.window._js_execute_signal.emit(code, tab_index if tab_index is not None else -1, qid)
            try:
                result = result_q.get(timeout=15)
                self._send_json(result)
            except queue.Empty:
                self._send_json({"error": "JS execution timed out"}, 504)

        elif path == "/navigate":
            url = body.get("url", "")
            tab_index = body.get("tab_index")
            if not url:
                self._send_json({"error": "url is required"}, 400)
                return
            result_q = queue.Queue()
            qid = self.window.register_queue(result_q)
            self.window._navigate_signal.emit(url, tab_index if tab_index is not None else -1, qid)
            try:
                result = result_q.get(timeout=5)
                self._send_json(result)
            except queue.Empty:
                self._send_json({"error": "Navigate timed out"}, 504)

        elif path == "/tabs":
            url = body.get("url")
            result_q = queue.Queue()
            qid = self.window.register_queue(result_q)
            self.window._new_tab_signal.emit(url or "", qid)
            try:
                result = result_q.get(timeout=5)
                self._send_json(result)
            except queue.Empty:
                self._send_json({"error": "New tab timed out"}, 504)

        elif path == "/tabs/close":
            index = body.get("index", 0)
            self._send_json(self.window.api_close_tab_idx(index))

        else:
            self._send_json({"error": "Not found"}, 404)


# ─── Main ────────────────────────────────────────────────────────────────────

def run_profile_process(profile_id, relay_port, api_port=None):
    """Entry point for a subprocess that runs a single profile window.
    Each subprocess gets its own Chromium instance with its own --proxy-server."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    relay = ProxyRelay(relay_port)
    relay.start()

    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        f"--proxy-server=http://127.0.0.1:{relay_port} "
        "--proxy-bypass-list=<-loopback> "
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp "
        "--disable-features=WebRtcHideLocalIpsWithMdns"
    )

    app = QApplication([sys.argv[0], "--profile", profile_id])
    app.setApplicationName(f"{APP_NAME} - {profile_id}")
    app.setStyleSheet(DARK_STYLE)

    pm = ProfileManager()
    config = pm.get_profile(profile_id)
    if not config:
        print(f"[GhostSurf] Profile '{profile_id}' not found")
        sys.exit(1)

    # Apply proxy to relay
    proxy_config = config.get("proxy", {})
    if proxy_config.get("enabled"):
        relay.set_upstream(
            proxy_config.get("host", ""),
            proxy_config.get("port", 0),
            proxy_config.get("type", "http"),
            proxy_config.get("username", ""),
            proxy_config.get("password", ""),
        )

    window = ProfileWindow(profile_id, config, pm, relay_port, relay=relay)
    if api_port:
        window.start_api(api_port)
    window.show()

    ret = app.exec()
    relay.stop()
    sys.exit(ret)


def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # If launched as a profile subprocess
    if "--profile" in sys.argv:
        idx = sys.argv.index("--profile")
        profile_id = sys.argv[idx + 1]
        relay_port = int(sys.argv[sys.argv.index("--relay-port") + 1]) if "--relay-port" in sys.argv else LOCAL_PROXY_PORT
        api_port = int(sys.argv[sys.argv.index("--api-port") + 1]) if "--api-port" in sys.argv else None
        run_profile_process(profile_id, relay_port, api_port)
        return

    # Otherwise, run the launcher
    # Launcher doesn't need a proxy relay itself
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = ""

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(DARK_STYLE)

    launcher = GhostSurfLauncher()
    launcher.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
