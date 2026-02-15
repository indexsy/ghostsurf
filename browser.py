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

// Spoof canvas fingerprint
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx) {
        const imageData = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] ^= 1;     // tiny noise
        }
        ctx.putImageData(imageData, 0, 0);
    }
    return origToDataURL.apply(this, arguments);
};

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


# ─── Main Browser Window ────────────────────────────────────────────────────

class GhostSurfBrowser(QMainWindow):
    """Main browser window with multi-profile support."""

    def __init__(self, proxy_relay):
        super().__init__()
        self.proxy_relay = proxy_relay
        self.profile_manager = ProfileManager()
        self.current_profile_id = "default"
        self.qt_profiles = {}  # profile_id -> QWebEngineProfile
        self.tabs = []  # list of BrowserTab
        self.api_server = None

        self._setup_ui()
        self._setup_shortcuts()
        self._switch_profile("default")
        self._new_tab()

        # Start API server
        self._start_api_server()

    def _setup_ui(self):
        self.setWindowTitle(f"{APP_NAME} - Privacy Browser")
        self.resize(1400, 900)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Top toolbar ──
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        self.addToolBar(toolbar)

        # Profile selector
        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(180)
        self._refresh_profile_combo()
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        toolbar.addWidget(QLabel("  Profile: "))
        toolbar.addWidget(self.profile_combo)
        toolbar.addSeparator()

        # Navigation buttons
        self.back_btn = QPushButton("<")
        self.back_btn.setFixedSize(32, 32)
        self.back_btn.setToolTip("Back")
        self.back_btn.clicked.connect(self._go_back)
        toolbar.addWidget(self.back_btn)

        self.fwd_btn = QPushButton(">")
        self.fwd_btn.setFixedSize(32, 32)
        self.fwd_btn.setToolTip("Forward")
        self.fwd_btn.clicked.connect(self._go_forward)
        toolbar.addWidget(self.fwd_btn)

        self.reload_btn = QPushButton("R")
        self.reload_btn.setFixedSize(32, 32)
        self.reload_btn.setToolTip("Reload")
        self.reload_btn.clicked.connect(self._reload)
        toolbar.addWidget(self.reload_btn)

        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL or search...")
        self.url_bar.returnPressed.connect(self._navigate)
        toolbar.addWidget(self.url_bar)

        # Action buttons
        self.new_tab_btn = QPushButton("+")
        self.new_tab_btn.setFixedSize(32, 32)
        self.new_tab_btn.setToolTip("New Tab (Cmd+T)")
        self.new_tab_btn.clicked.connect(self._new_tab)
        toolbar.addWidget(self.new_tab_btn)

        # Reddit quick-nav
        self.reddit_btn = QPushButton("Reddit")
        self.reddit_btn.setToolTip("Go to Reddit")
        self.reddit_btn.clicked.connect(lambda: self._quick_nav("https://www.reddit.com"))
        toolbar.addWidget(self.reddit_btn)

        toolbar.addSeparator()

        # Profile management button
        self.manage_btn = QPushButton("Profiles")
        self.manage_btn.setToolTip("Manage Profiles")
        self.manage_btn.clicked.connect(self._show_profile_manager)
        toolbar.addWidget(self.manage_btn)

        # Menu button
        self.menu_btn = QPushButton("=")
        self.menu_btn.setFixedSize(32, 32)
        self.menu_btn.setToolTip("Menu")
        self.menu_btn.clicked.connect(self._show_menu)
        toolbar.addWidget(self.menu_btn)

        # ── Tab widget ──
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setMovable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        main_layout.addWidget(self.tab_widget)

        # ── Status bar ──
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.profile_label = QLabel()
        self.proxy_label = QLabel()
        self.api_label = QLabel()
        self.status_bar.addPermanentWidget(self.profile_label)
        self.status_bar.addPermanentWidget(self.proxy_label)
        self.status_bar.addPermanentWidget(self.api_label)
        self._update_status_bar()

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+T"), self, self._new_tab)
        QShortcut(QKeySequence("Ctrl+W"), self, self._close_current_tab)
        QShortcut(QKeySequence("Ctrl+L"), self, lambda: self.url_bar.setFocus())
        QShortcut(QKeySequence("Ctrl+R"), self, self._reload)
        QShortcut(QKeySequence("Ctrl+Shift+N"), self, self._new_incognito_tab)
        # Cmd variants for macOS
        QShortcut(QKeySequence("Meta+T"), self, self._new_tab)
        QShortcut(QKeySequence("Meta+W"), self, self._close_current_tab)
        QShortcut(QKeySequence("Meta+L"), self, lambda: self.url_bar.setFocus())
        QShortcut(QKeySequence("Meta+R"), self, self._reload)

    def _refresh_profile_combo(self):
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        for pid, pdata in self.profile_manager.list_profiles().items():
            label = f"{pdata['name']}"
            if pdata.get("notes"):
                label += f" ({pdata['notes']})"
            self.profile_combo.addItem(label, pid)
        # Select current
        idx = self.profile_combo.findData(self.current_profile_id)
        if idx >= 0:
            self.profile_combo.setCurrentIndex(idx)
        self.profile_combo.blockSignals(False)

    def _on_profile_changed(self, index):
        pid = self.profile_combo.itemData(index)
        if pid and pid != self.current_profile_id:
            self._switch_profile(pid)

    def _get_qt_profile(self, profile_id):
        """Get or create an isolated QWebEngineProfile for the given profile."""
        if profile_id not in self.qt_profiles:
            storage_path = self.profile_manager.get_storage_path(profile_id)
            qt_profile = QWebEngineProfile(profile_id, self)
            qt_profile.setPersistentStoragePath(storage_path)
            qt_profile.setCachePath(os.path.join(storage_path, "cache"))
            qt_profile.setPersistentCookiesPolicy(
                QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies
            )

            profile_config = self.profile_manager.get_profile(profile_id)
            if profile_config:
                ua = profile_config.get("user_agent", DEFAULT_USER_AGENTS[0])
                qt_profile.setHttpUserAgent(ua)

            self.qt_profiles[profile_id] = qt_profile

        return self.qt_profiles[profile_id]

    def _switch_profile(self, profile_id):
        """Switch active profile - applies proxy, updates UI."""
        self.current_profile_id = profile_id
        profile_config = self.profile_manager.get_profile(profile_id)
        if not profile_config:
            return

        # Apply proxy
        self._apply_proxy(profile_config.get("proxy", {}))

        # Update UI color accent
        color = profile_config.get("color", "#e94560")
        self._update_accent_color(color)
        self._update_status_bar()

        # Update combo selection
        idx = self.profile_combo.findData(profile_id)
        if idx >= 0:
            self.profile_combo.blockSignals(True)
            self.profile_combo.setCurrentIndex(idx)
            self.profile_combo.blockSignals(False)

    def _apply_proxy(self, proxy_config):
        """Apply proxy by updating the local relay's upstream target.

        QtWebEngine/Chromium ignores QNetworkProxy entirely. Instead,
        Chromium is started with --proxy-server=http://127.0.0.1:LOCAL_PROXY_PORT
        and we dynamically swap the upstream that the local relay forwards to.
        """
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

    def _update_accent_color(self, color):
        """Update the tab bar accent color to match profile."""
        accent_style = f"""
        QTabBar::tab:selected {{
            border-bottom: 2px solid {color};
            color: {color};
        }}
        QGroupBox {{
            color: {color};
        }}
        """
        # Apply on top of dark theme
        current = self.styleSheet()
        # Remove old accent overrides
        if hasattr(self, '_accent_style'):
            current = current.replace(self._accent_style, '')
        self._accent_style = accent_style
        self.setStyleSheet(current + accent_style)

    def _update_status_bar(self):
        profile = self.profile_manager.get_profile(self.current_profile_id)
        if not profile:
            return

        self.profile_label.setText(f"  Profile: {profile['name']}  ")

        proxy = profile.get("proxy", {})
        if proxy.get("enabled"):
            self.proxy_label.setText(f"  Proxy: {proxy['type'].upper()} {proxy['host']}:{proxy['port']}  ")
            self.proxy_label.setStyleSheet("color: #4ecca3;")
        else:
            self.proxy_label.setText("  Proxy: OFF  ")
            self.proxy_label.setStyleSheet("color: #666;")

        if self.api_server:
            self.api_label.setText(f"  API: :{API_DEFAULT_PORT}  ")
            self.api_label.setStyleSheet("color: #4ecca3;")
        else:
            self.api_label.setText("  API: OFF  ")

    # ── Tab Management ──

    def _new_tab(self, url=None):
        profile_config = self.profile_manager.get_profile(self.current_profile_id)
        qt_profile = self._get_qt_profile(self.current_profile_id)

        if url is None:
            url = profile_config.get("homepage", "https://www.reddit.com") if profile_config else "https://www.reddit.com"

        privacy_config = profile_config.get("privacy", {}) if profile_config else {}
        user_agent = profile_config.get("user_agent", DEFAULT_USER_AGENTS[0]) if profile_config else DEFAULT_USER_AGENTS[0]

        tab_index = self.tab_widget.count()
        tab = BrowserTab(tab_index, qt_profile, privacy_config, user_agent, url)
        tab.title_changed.connect(self._on_title_changed)
        tab.url_changed.connect(self._on_url_changed)

        self.tabs.append(tab)
        idx = self.tab_widget.addTab(tab, "Loading...")
        self.tab_widget.setCurrentIndex(idx)

        return idx

    def _new_incognito_tab(self):
        """Open a tab with a fresh off-the-record profile."""
        profile_config = self.profile_manager.get_profile(self.current_profile_id)
        otr_profile = QWebEngineProfile(self)  # off-the-record (no storage path)

        privacy_config = profile_config.get("privacy", {}) if profile_config else {}
        user_agent = profile_config.get("user_agent", DEFAULT_USER_AGENTS[0]) if profile_config else DEFAULT_USER_AGENTS[0]
        otr_profile.setHttpUserAgent(user_agent)

        url = "https://www.reddit.com"
        tab_index = self.tab_widget.count()
        tab = BrowserTab(tab_index, otr_profile, privacy_config, user_agent, url)
        tab.title_changed.connect(self._on_title_changed)
        tab.url_changed.connect(self._on_url_changed)

        self.tabs.append(tab)
        idx = self.tab_widget.addTab(tab, "[Private] Loading...")
        self.tab_widget.setCurrentIndex(idx)

    def _close_tab(self, index):
        if self.tab_widget.count() > 1:
            widget = self.tab_widget.widget(index)
            self.tab_widget.removeTab(index)
            if widget in self.tabs:
                self.tabs.remove(widget)
            widget.deleteLater()
            # Reindex remaining tabs
            for i, tab in enumerate(self.tabs):
                tab.tab_index = i

    def _close_current_tab(self):
        self._close_tab(self.tab_widget.currentIndex())

    def _on_tab_changed(self, index):
        widget = self.tab_widget.widget(index)
        if widget and hasattr(widget, 'current_url'):
            self.url_bar.setText(widget.current_url())

    def _on_title_changed(self, tab_index, title):
        # Find the tab in tab widget
        for i in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(i)
            if hasattr(widget, 'tab_index') and widget.tab_index == tab_index:
                short_title = title[:30] + "..." if len(title) > 30 else title
                self.tab_widget.setTabText(i, short_title)
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

        # Check if it's a search query
        if " " in url or ("." not in url and "/" not in url):
            url = f"https://duckduckgo.com/?q={url}"
        elif not url.startswith(("http://", "https://")):
            url = "https://" + url

        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'navigate'):
            current.navigate(url)

    def _go_back(self):
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'web_view'):
            current.web_view.back()

    def _go_forward(self):
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'web_view'):
            current.web_view.forward()

    def _reload(self):
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'web_view'):
            current.web_view.reload()

    def _quick_nav(self, url):
        current = self.tab_widget.currentWidget()
        if current and hasattr(current, 'navigate'):
            current.navigate(url)
            self.url_bar.setText(url)

    # ── Menus ──

    def _show_menu(self):
        menu = QMenu(self)

        new_tab = menu.addAction("New Tab")
        new_tab.triggered.connect(self._new_tab)

        private_tab = menu.addAction("New Private Tab")
        private_tab.triggered.connect(self._new_incognito_tab)

        menu.addSeparator()

        # Quick profile switcher
        profiles_menu = menu.addMenu("Switch Profile")
        for pid, pdata in self.profile_manager.list_profiles().items():
            label = pdata["name"]
            if pdata.get("notes"):
                label += f" ({pdata['notes']})"
            if pid == self.current_profile_id:
                label += " *"
            action = profiles_menu.addAction(label)
            action.triggered.connect(partial(self._switch_profile_and_update, pid))

        menu.addSeparator()

        manage = menu.addAction("Manage Profiles...")
        manage.triggered.connect(self._show_profile_manager)

        clear_data = menu.addAction("Clear Profile Data")
        clear_data.triggered.connect(self._clear_profile_data)

        menu.addSeparator()

        reddit_home = menu.addAction("Reddit Home")
        reddit_home.triggered.connect(lambda: self._quick_nav("https://www.reddit.com"))

        reddit_new = menu.addAction("Reddit (new.reddit)")
        reddit_new.triggered.connect(lambda: self._quick_nav("https://new.reddit.com"))

        reddit_old = menu.addAction("Reddit (old.reddit)")
        reddit_old.triggered.connect(lambda: self._quick_nav("https://old.reddit.com"))

        menu.addSeparator()

        about = menu.addAction("About GhostSurf")
        about.triggered.connect(self._show_about)

        menu.exec(self.menu_btn.mapToGlobal(self.menu_btn.rect().bottomLeft()))

    def _switch_profile_and_update(self, profile_id):
        self._switch_profile(profile_id)
        self._refresh_profile_combo()
        # Open homepage in new tab
        self._new_tab()

    def _show_about(self):
        QMessageBox.about(
            self, f"About {APP_NAME}",
            f"<h2>{APP_NAME} v{APP_VERSION}</h2>"
            f"<p>Privacy browser with multi-profile support.</p>"
            f"<p>Features:</p>"
            f"<ul>"
            f"<li>Isolated profiles with separate cookies/storage</li>"
            f"<li>Per-profile proxy (HTTP/SOCKS5)</li>"
            f"<li>WebRTC blocking, canvas/WebGL spoofing</li>"
            f"<li>REST API for OpenClaw integration</li>"
            f"<li>DuckDuckGo default search</li>"
            f"</ul>"
            f"<p>API running on port {API_DEFAULT_PORT}</p>"
        )

    def _clear_profile_data(self):
        reply = QMessageBox.question(
            self, "Clear Profile Data",
            f"Clear all browsing data for profile '{self.current_profile_id}'?\n"
            "This will delete cookies, cache, and local storage.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            qt_profile = self.qt_profiles.get(self.current_profile_id)
            if qt_profile:
                qt_profile.clearAllVisitedLinks()
                qt_profile.clearHttpCache()
                cookie_store = qt_profile.cookieStore()
                cookie_store.deleteAllCookies()
                self.status_bar.showMessage("Profile data cleared.", 3000)

    # ── Profile Manager Dialog ──

    def _show_profile_manager(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Profile Manager")
        dialog.setMinimumSize(600, 500)

        layout = QVBoxLayout(dialog)

        # Profile list
        self.profile_list = QListWidget()
        self._refresh_profile_list()
        layout.addWidget(self.profile_list)

        # Buttons
        btn_layout = QHBoxLayout()

        add_btn = QPushButton("+ New Profile")
        add_btn.clicked.connect(lambda: self._add_profile(dialog))
        btn_layout.addWidget(add_btn)

        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(lambda: self._edit_profile(dialog))
        btn_layout.addWidget(edit_btn)

        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(lambda: self._delete_profile(dialog))
        btn_layout.addWidget(delete_btn)

        duplicate_btn = QPushButton("Duplicate")
        duplicate_btn.clicked.connect(lambda: self._duplicate_profile(dialog))
        btn_layout.addWidget(duplicate_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

        dialog.exec()
        self._refresh_profile_combo()

    def _refresh_profile_list(self):
        self.profile_list.clear()
        for pid, pdata in self.profile_manager.list_profiles().items():
            label = f"{pdata['name']} [{pid}]"
            if pdata.get("notes"):
                label += f" - {pdata['notes']}"
            proxy = pdata.get("proxy", {})
            if proxy.get("enabled"):
                label += f" | Proxy: {proxy['type']}://{proxy['host']}:{proxy['port']}"
            if pid == self.current_profile_id:
                label += " (active)"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, pid)
            self.profile_list.addItem(item)

    def _add_profile(self, parent_dialog):
        dialog = ProfileDialog(parent_dialog)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            pid = data["id"]
            if not pid:
                QMessageBox.warning(parent_dialog, "Error", "Profile ID is required.")
                return
            if pid in self.profile_manager.profiles:
                QMessageBox.warning(parent_dialog, "Error", f"Profile '{pid}' already exists.")
                return
            self.profile_manager.create_profile(pid, data["config"])
            self._refresh_profile_list()

    def _edit_profile(self, parent_dialog):
        item = self.profile_list.currentItem()
        if not item:
            return
        pid = item.data(Qt.ItemDataRole.UserRole)
        pdata = self.profile_manager.get_profile(pid)
        dialog = ProfileDialog(parent_dialog, profile_data=pdata, profile_id=pid)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()
            self.profile_manager.update_profile(pid, data["config"])
            self._refresh_profile_list()
            if pid == self.current_profile_id:
                self._switch_profile(pid)

    def _delete_profile(self, parent_dialog):
        item = self.profile_list.currentItem()
        if not item:
            return
        pid = item.data(Qt.ItemDataRole.UserRole)
        if pid == "default":
            QMessageBox.warning(parent_dialog, "Error", "Cannot delete the default profile.")
            return
        reply = QMessageBox.question(
            parent_dialog, "Delete Profile",
            f"Delete profile '{pid}'? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if pid == self.current_profile_id:
                self._switch_profile("default")
            self.profile_manager.delete_profile(pid)
            self._refresh_profile_list()

    def _duplicate_profile(self, parent_dialog):
        item = self.profile_list.currentItem()
        if not item:
            return
        pid = item.data(Qt.ItemDataRole.UserRole)
        pdata = self.profile_manager.get_profile(pid)
        if pdata:
            import copy
            new_data = copy.deepcopy(pdata)
            new_id = f"{pid}-copy"
            counter = 1
            while new_id in self.profile_manager.profiles:
                new_id = f"{pid}-copy-{counter}"
                counter += 1
            new_data["name"] = f"{new_data['name']} (Copy)"
            self.profile_manager.create_profile(new_id, new_data)
            self._refresh_profile_list()

    # ── API Server ──

    def _start_api_server(self):
        """Start the REST API server for OpenClaw integration."""
        handler = partial(APIHandler, self)
        try:
            self.api_server = HTTPServer(("127.0.0.1", API_DEFAULT_PORT), handler)
            thread = threading.Thread(target=self.api_server.serve_forever, daemon=True)
            thread.start()
            self._update_status_bar()
            print(f"[GhostSurf] API server started on http://127.0.0.1:{API_DEFAULT_PORT}")
        except OSError as e:
            print(f"[GhostSurf] API server failed to start: {e}")
            self.api_server = None

    def closeEvent(self, event):
        if self.api_server:
            self.api_server.shutdown()
        self.proxy_relay.stop()
        super().closeEvent(event)

    # ── API Methods (called from API handler) ──

    def api_get_status(self):
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "active_profile": self.current_profile_id,
            "tabs": self.tab_widget.count(),
            "profiles": list(self.profile_manager.profiles.keys()),
        }

    def api_list_profiles(self):
        return self.profile_manager.list_profiles()

    def api_get_tabs(self):
        result = []
        for i in range(self.tab_widget.count()):
            widget = self.tab_widget.widget(i)
            if hasattr(widget, 'current_url'):
                result.append({
                    "index": i,
                    "url": widget.current_url(),
                    "title": widget.current_title(),
                })
        return result

    def api_navigate(self, url, tab_index=None):
        """Navigate a tab to a URL. Thread-safe via signal."""
        QTimer.singleShot(0, lambda: self._api_navigate_impl(url, tab_index))
        return {"status": "ok", "url": url}

    def _api_navigate_impl(self, url, tab_index):
        if tab_index is not None and 0 <= tab_index < self.tab_widget.count():
            widget = self.tab_widget.widget(tab_index)
        else:
            widget = self.tab_widget.currentWidget()
        if widget and hasattr(widget, 'navigate'):
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            widget.navigate(url)
            self.url_bar.setText(url)

    def api_new_tab(self, url=None):
        result = {"status": "ok"}
        QTimer.singleShot(0, lambda: self._api_new_tab_impl(url))
        return result

    def _api_new_tab_impl(self, url):
        self._new_tab(url)

    def api_close_tab(self, index):
        QTimer.singleShot(0, lambda: self._close_tab(index))
        return {"status": "ok"}

    def api_switch_profile(self, profile_id):
        if profile_id not in self.profile_manager.profiles:
            return {"error": f"Profile '{profile_id}' not found"}
        QTimer.singleShot(0, lambda: self._switch_profile_and_update(profile_id))
        return {"status": "ok", "profile": profile_id}

    def api_create_profile(self, profile_id, config):
        self.profile_manager.create_profile(profile_id, config)
        QTimer.singleShot(0, self._refresh_profile_combo)
        return {"status": "ok", "profile": profile_id}

    def api_get_page_text(self, tab_index=None):
        """Get page text content - returns async result placeholder."""
        return {"status": "ok", "note": "Use /tabs endpoint to get current URLs, then fetch content via the browser"}

    def api_snapshot(self, tab_index=None):
        """Get a lightweight snapshot of the current page state."""
        tabs = self.api_get_tabs()
        return {
            "active_profile": self.current_profile_id,
            "tabs": tabs,
            "active_tab": self.tab_widget.currentIndex(),
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
            self._send_json({
                "error": "Not found",
                "available_post": ["/navigate", "/tabs", "/tabs/close", "/profiles", "/profiles/switch", "/snapshot"]
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


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # Start local proxy relay BEFORE Qt/Chromium init
    relay = ProxyRelay(LOCAL_PROXY_PORT)
    relay.start()

    # Tell Chromium to route all traffic through our local relay
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        f"--proxy-server=http://127.0.0.1:{LOCAL_PROXY_PORT} "
        "--proxy-bypass-list=<-loopback>"  # only bypass actual loopback
    )

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    # Apply dark theme
    app.setStyleSheet(DARK_STYLE)

    browser = GhostSurfBrowser(relay)
    browser.show()

    ret = app.exec()
    relay.stop()
    sys.exit(ret)


if __name__ == "__main__":
    main()
