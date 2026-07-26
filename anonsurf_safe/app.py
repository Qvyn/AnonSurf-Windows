from __future__ import annotations

import argparse
import atexit
import os
import sys
import threading
import webbrowser
from collections.abc import Callable

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QColor,
    QCloseEvent,
    QFont,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from .config import Settings
from .http_socks_proxy import HTTPToSocksBridge
from .tor_controller import TorController, TorError, find_tor_candidates
from .verification import VerificationError, check_tor
from .windows_proxy import (
    ProxyError,
    backup_exists,
    enable_local_proxy,
    force_disable_proxy,
    restore_backup,
)

TOR_DOWNLOAD_URL = "https://www.torproject.org/download/tor/"
HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000
HEALTH_RETRY_INTERVAL_MS = 60 * 1000
HEALTH_FAILURE_LIMIT = 2

STYLE_SHEET = """
QMainWindow, QWidget#root {
    background: #0b1220;
    color: #e5edf8;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QFrame#headerCard, QGroupBox {
    background: #111b2e;
    border: 1px solid #223250;
    border-radius: 12px;
}
QGroupBox {
    margin-top: 12px;
    padding: 16px 14px 14px 14px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
    color: #9fb2cc;
}
QLabel#title {
    font-size: 22pt;
    font-weight: 700;
    color: #f4f8ff;
}
QLabel#subtitle, QLabel#muted {
    color: #9fb2cc;
}
QLabel#warning {
    color: #c9d6e8;
}
QLabel#statusBadge {
    border-radius: 10px;
    padding: 5px 11px;
    font-weight: 700;
}
QLineEdit, QPlainTextEdit {
    background: #08101d;
    border: 1px solid #2a3d5f;
    border-radius: 7px;
    color: #e8f0fb;
    selection-background-color: #1877d5;
}
QLineEdit {
    padding: 8px 10px;
}
QPlainTextEdit {
    padding: 8px;
    font-family: "Cascadia Mono", "Consolas";
    font-size: 9pt;
}
QPushButton {
    background: #1a2941;
    border: 1px solid #314765;
    border-radius: 7px;
    color: #e7eef8;
    padding: 8px 13px;
    font-weight: 600;
}
QPushButton:hover {
    background: #243754;
    border-color: #4d6f99;
}
QPushButton:pressed {
    background: #142136;
}
QPushButton:disabled {
    background: #111a28;
    border-color: #1e2a3d;
    color: #607087;
}
QPushButton#primaryButton {
    background: #0878d1;
    border-color: #2999ef;
    color: white;
}
QPushButton#primaryButton:hover {
    background: #1590e8;
}
QPushButton#dangerButton {
    color: #ffb6b6;
}
"""


def make_app_icon(active: bool = False) -> QIcon:
    """Create a crisp runtime icon without depending on external image files."""
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    accent = QColor("#20c997" if active else "#2d8fe8")
    shield = QPainterPath()
    shield.moveTo(32, 4)
    shield.lineTo(55, 13)
    shield.lineTo(52, 36)
    shield.cubicTo(49, 49, 40, 57, 32, 60)
    shield.cubicTo(24, 57, 15, 49, 12, 36)
    shield.lineTo(9, 13)
    shield.closeSubpath()
    painter.setPen(QPen(QColor("#dce9f8"), 2.2))
    painter.setBrush(accent)
    painter.drawPath(shield)

    painter.setPen(QPen(QColor("#07111f"), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawLine(24, 32, 30, 38)
    painter.drawLine(30, 38, 42, 24)
    painter.end()
    return QIcon(pixmap)


class AppWindow(QMainWindow):
    log_received = Signal(str)
    ui_requested = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.settings = Settings.load()
        self.tor: TorController | None = None
        self.bridge: HTTPToSocksBridge | None = None
        self.active = False
        self.busy = False
        self._closing = False
        self._exit_requested = False
        self._tray_hint_shown = False
        self._health_check_running = False
        self._health_failures = 0

        self.log_received.connect(self._append_log)
        self.ui_requested.connect(self._execute_ui_request)

        self.setWindowTitle("AnonSurf Safe")
        self.setWindowIcon(make_app_icon())
        self.resize(920, 720)
        self.setMinimumSize(760, 600)

        self._build_ui()
        self._build_tray()
        self._update_controls()
        self._set_status("Disabled", "off")

        if not self.path_edit.text():
            candidates = find_tor_candidates()
            if candidates:
                self.path_edit.setText(str(candidates[0]))

        QTimer.singleShot(HEALTH_CHECK_INTERVAL_MS, self._health_tick)
        if backup_exists():
            QTimer.singleShot(250, self._offer_crash_recovery)
        atexit.register(self._best_effort_cleanup)

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(13)

        header = QFrame()
        header.setObjectName("headerCard")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 16, 18, 16)
        icon_label = QLabel()
        icon_label.setPixmap(make_app_icon().pixmap(54, 54))
        header_layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        title_column = QVBoxLayout()
        title = QLabel("AnonSurf Safe")
        title.setObjectName("title")
        subtitle = QLabel(
            "A recoverable Windows HTTP proxy powered by the official Tor daemon."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        title_column.addWidget(title)
        title_column.addWidget(subtitle)
        header_layout.addLayout(title_column, 1)
        outer.addWidget(header)

        tor_box = QGroupBox("Official Tor executable")
        tor_layout = QVBoxLayout(tor_box)
        path_row = QHBoxLayout()
        self.path_edit = QLineEdit(self.settings.tor_path)
        self.path_edit.setPlaceholderText("Select tor.exe from the Tor Expert Bundle")
        path_row.addWidget(self.path_edit, 1)
        browse_button = QPushButton("Browse…")
        browse_button.clicked.connect(self.browse_tor)
        path_row.addWidget(browse_button)
        download_button = QPushButton("Official download")
        download_button.clicked.connect(lambda: webbrowser.open(TOR_DOWNLOAD_URL))
        path_row.addWidget(download_button)
        tor_layout.addLayout(path_row)
        path_help = QLabel(
            "Extract the Windows x86_64 Tor Expert Bundle, then select its tor.exe."
        )
        path_help.setObjectName("muted")
        tor_layout.addWidget(path_help)
        outer.addWidget(tor_box)

        connection_box = QGroupBox("Connection")
        connection_layout = QVBoxLayout(connection_box)
        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Status"))
        self.status_badge = QLabel("Disabled")
        self.status_badge.setObjectName("statusBadge")
        status_row.addWidget(self.status_badge)
        status_row.addSpacing(12)
        self.ip_label = QLabel("Tor IP: not checked")
        self.ip_label.setObjectName("muted")
        status_row.addWidget(self.ip_label)
        status_row.addStretch(1)
        connection_layout.addLayout(status_row)

        button_row = QHBoxLayout()
        self.toggle_button = QPushButton("Enable Tor proxy")
        self.toggle_button.setObjectName("primaryButton")
        self.toggle_button.clicked.connect(self.toggle)
        button_row.addWidget(self.toggle_button)
        self.identity_button = QPushButton("New identity")
        self.identity_button.clicked.connect(self.new_identity)
        button_row.addWidget(self.identity_button)
        self.refresh_button = QPushButton("Refresh connection")
        self.refresh_button.clicked.connect(self.refresh)
        button_row.addWidget(self.refresh_button)
        self.restore_button = QPushButton("Restore Windows proxy")
        self.restore_button.clicked.connect(self.restore_proxy_now)
        button_row.addWidget(self.restore_button)
        button_row.addStretch(1)
        connection_layout.addLayout(button_row)
        outer.addWidget(connection_box)

        warning_box = QGroupBox("Important")
        warning_layout = QVBoxLayout(warning_box)
        warning = QLabel(
            "This is not a VPN. Only applications that honor the Windows proxy are routed. "
            "Games, launchers, UDP/QUIC, and software with independent networking can bypass it. "
            "Tor Browser remains the safer choice for anonymous web browsing."
        )
        warning.setObjectName("warning")
        warning.setWordWrap(True)
        warning_layout.addWidget(warning)
        outer.addWidget(warning_box)

        log_box = QGroupBox("Activity log")
        log_layout = QVBoxLayout(log_box)
        self.log_widget = QPlainTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMaximumBlockCount(2500)
        self.log_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        log_layout.addWidget(self.log_widget, 1)
        log_buttons = QHBoxLayout()
        log_buttons.addStretch(1)
        clear_button = QPushButton("Clear log")
        clear_button.clicked.connect(self.log_widget.clear)
        log_buttons.addWidget(clear_button)
        log_layout.addLayout(log_buttons)
        outer.addWidget(log_box, 1)

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(make_app_icon(), self)
        self.tray.setToolTip("AnonSurf Safe — Disabled")
        menu = QMenu()
        self.tray_open_action = QAction("Open AnonSurf Safe", self)
        self.tray_open_action.triggered.connect(self.show_from_tray)
        menu.addAction(self.tray_open_action)
        menu.addSeparator()
        self.tray_toggle_action = QAction("Enable Tor proxy", self)
        self.tray_toggle_action.triggered.connect(self.toggle)
        menu.addAction(self.tray_toggle_action)
        self.tray_refresh_action = QAction("Refresh connection", self)
        self.tray_refresh_action.triggered.connect(self.refresh)
        menu.addAction(self.tray_refresh_action)
        self.tray_identity_action = QAction("New identity", self)
        self.tray_identity_action.triggered.connect(self.new_identity)
        menu.addAction(self.tray_identity_action)
        menu.addSeparator()
        self.tray_exit_action = QAction("Exit", self)
        self.tray_exit_action.triggered.connect(self.request_exit)
        menu.addAction(self.tray_exit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.show_from_tray()

    def show_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def log(self, message: str) -> None:
        self.log_received.emit(message)

    def dispatch(self, callback: Callable[[], None]) -> None:
        self.ui_requested.emit(callback)

    def _append_log(self, message: str) -> None:
        self.log_widget.appendPlainText(message.rstrip())
        scrollbar = self.log_widget.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    @staticmethod
    def _execute_ui_request(callback: Callable[[], None]) -> None:
        callback()

    def _set_status(self, text: str, state: str) -> None:
        colors = {
            "off": ("#172235", "#92a3ba"),
            "busy": ("#3a2e12", "#ffd36b"),
            "on": ("#12352f", "#5ce1b7"),
            "error": ("#3a1c24", "#ff9aa9"),
        }
        background, foreground = colors[state]
        self.status_badge.setText(text)
        self.status_badge.setStyleSheet(
            f"background: {background}; color: {foreground}; "
            "border: 1px solid rgba(255,255,255,0.08);"
        )
        self.tray.setToolTip(f"AnonSurf Safe — {text}")
        icon = make_app_icon(self.active and state == "on")
        self.tray.setIcon(icon)
        self.setWindowIcon(icon)

    def _update_controls(self) -> None:
        active_controls = self.active and not self.busy
        self.toggle_button.setEnabled(not self.busy)
        self.restore_button.setEnabled(not self.busy and not self.active)
        self.identity_button.setEnabled(active_controls)
        self.refresh_button.setEnabled(active_controls)
        self.path_edit.setEnabled(not self.busy and not self.active)

        toggle_text = "Disable Tor proxy" if self.active else "Enable Tor proxy"
        self.toggle_button.setText(toggle_text)
        self.tray_toggle_action.setText(toggle_text)
        self.tray_toggle_action.setEnabled(not self.busy)
        self.tray_refresh_action.setEnabled(active_controls)
        self.tray_identity_action.setEnabled(active_controls)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self._update_controls()

    def _offer_crash_recovery(self) -> None:
        answer = QMessageBox.question(
            self,
            "Proxy recovery found",
            "AnonSurf Safe found a saved Windows proxy configuration from an interrupted "
            "session. Restore it now?",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.restore_proxy_now()

    def browse_tor(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select official tor.exe",
            self.path_edit.text(),
            "Tor executable (tor.exe);;Executable files (*.exe);;All files (*)",
        )
        if path:
            self.path_edit.setText(path)
            self.settings.tor_path = path
            self.settings.save()

    def toggle(self) -> None:
        if self.busy:
            return
        if self.active:
            self._run_worker(self.disable)
            return
        self.settings.tor_path = self.path_edit.text().strip()
        self.settings.save()
        self._run_worker(self.enable)

    def _run_worker(self, target: Callable[[], None]) -> None:
        self._set_busy(True)

        def runner() -> None:
            try:
                target()
            except Exception as exc:
                self.log(f"ERROR: {exc}")
                if not self._exit_requested:
                    self.dispatch(
                        lambda exc=exc: QMessageBox.critical(self, "AnonSurf Safe", str(exc))
                    )
            finally:
                self.dispatch(self._worker_finished)

        threading.Thread(target=runner, daemon=True).start()

    def _worker_finished(self) -> None:
        self._set_busy(False)
        if not self._exit_requested:
            return
        if self.active:
            self._run_worker(self.disable)
        else:
            self._finalize_exit()

    def enable(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("AnonSurf Safe must be run on Windows.")

        self.dispatch(lambda: self._set_status("Starting Tor…", "busy"))
        tor = TorController(
            tor_path=self.settings.tor_path,
            socks_port=self.settings.socks_port,
            control_port=self.settings.control_port,
            logger=self.log,
        )
        bridge = HTTPToSocksBridge(
            listen_port=self.settings.http_proxy_port,
            socks_port=self.settings.socks_port,
            logger=self.log,
        )

        try:
            tor.start()
            bridge.start()
            is_tor, ip = check_tor(self.settings.http_proxy_port)
            if not is_tor:
                raise VerificationError(
                    f"The test endpoint did not identify {ip} as a Tor exit address."
                )
            enable_local_proxy(self.settings.http_proxy_port)
        except Exception:
            try:
                restore_backup()
            except Exception as restore_exc:
                self.log(f"Proxy restore also failed: {restore_exc}")
            bridge.stop()
            tor.stop()
            raise

        self.tor = tor
        self.bridge = bridge
        self.active = True
        self._health_failures = 0
        self.dispatch(lambda: self._set_status("Enabled and verified", "on"))
        self.dispatch(lambda ip=ip: self.ip_label.setText(f"Tor IP: {ip}"))
        self.dispatch(self._update_controls)
        self.log("Windows proxy enabled after Tor verification passed.")

    def disable(self) -> None:
        self.dispatch(lambda: self._set_status("Restoring proxy…", "busy"))
        restore_error: Exception | None = None
        try:
            restore_backup()
        except Exception as exc:
            restore_error = exc
            self.log(f"Unable to restore saved proxy settings: {exc}")

        if self.bridge:
            self.bridge.stop()
            self.bridge = None
        if self.tor:
            self.tor.stop()
            self.tor = None

        self.active = False
        self._health_failures = 0
        self.dispatch(lambda: self._set_status("Disabled", "off"))
        self.dispatch(lambda: self.ip_label.setText("Tor IP: not checked"))
        self.dispatch(self._update_controls)
        if restore_error:
            raise restore_error

    def new_identity(self) -> None:
        if self.busy or not self.tor or not self.active:
            return
        self._run_worker(self._new_identity)

    def _new_identity(self) -> None:
        tor = self.tor
        if tor is None or not self.active:
            return
        try:
            tor.new_identity()
            self.dispatch(lambda: self.ip_label.setText("Tor IP: circuit change requested"))
        except TorError as exc:
            raise RuntimeError(f"New identity failed: {exc}") from exc

    def refresh(self) -> None:
        if self.busy or not self.active:
            return
        self._run_worker(self._refresh_connection)

    def _refresh_connection(self) -> None:
        if not self.active:
            return

        self.dispatch(lambda: self._set_status("Refreshing connection…", "busy"))
        self.dispatch(lambda: self.ip_label.setText("Tor IP: reconnecting"))
        self.log("Refreshing connection: closing active proxy sockets and restarting Tor...")

        old_bridge, old_tor = self.bridge, self.tor
        self.bridge = None
        self.tor = None
        if old_bridge:
            old_bridge.stop()
        if old_tor:
            old_tor.stop()

        tor = TorController(
            tor_path=self.settings.tor_path,
            socks_port=self.settings.socks_port,
            control_port=self.settings.control_port,
            logger=self.log,
        )
        bridge = HTTPToSocksBridge(
            listen_port=self.settings.http_proxy_port,
            socks_port=self.settings.socks_port,
            logger=self.log,
        )

        try:
            tor.start()
            bridge.start()
            is_tor, ip = check_tor(self.settings.http_proxy_port)
            if not is_tor:
                raise VerificationError(
                    f"The test endpoint did not identify {ip} as a Tor exit address."
                )
            enable_local_proxy(self.settings.http_proxy_port)
        except Exception as exc:
            bridge.stop()
            tor.stop()
            self.active = False
            try:
                restore_backup()
            except Exception as restore_exc:
                self.log(f"Proxy restore also failed: {restore_exc}")
            self.dispatch(lambda: self._set_status("Disabled — refresh failed", "error"))
            self.dispatch(lambda: self.ip_label.setText("Tor IP: not checked"))
            self.dispatch(self._update_controls)
            raise RuntimeError(
                f"Connection refresh failed and the saved Windows proxy was restored: {exc}"
            ) from exc

        self.tor = tor
        self.bridge = bridge
        self.active = True
        self._health_failures = 0
        self.dispatch(lambda: self._set_status("Enabled and verified", "on"))
        self.dispatch(lambda ip=ip: self.ip_label.setText(f"Tor IP: {ip}"))
        self.dispatch(self._update_controls)
        self.log("Connection refreshed and verified successfully.")

    def restore_proxy_now(self) -> None:
        if self.active:
            QMessageBox.information(
                self,
                "Tor proxy is active",
                "Disable the Tor proxy first so the application can restore settings "
                "and stop Tor cleanly.",
            )
            return
        try:
            restored = restore_backup()
            if restored:
                self.log("Restored the saved Windows proxy configuration.")
                QMessageBox.information(
                    self,
                    "Proxy restored",
                    "The saved Windows proxy configuration was restored.",
                )
            elif (
                QMessageBox.question(
                    self,
                    "No backup found",
                    "No AnonSurf Safe backup exists. Disable the Windows manual proxy "
                    "as an emergency repair?",
                )
                == QMessageBox.StandardButton.Yes
            ):
                force_disable_proxy()
                self.log("Disabled the Windows manual proxy (no backup was available).")
        except ProxyError as exc:
            QMessageBox.critical(self, "Proxy restore failed", str(exc))

    def _health_tick(self) -> None:
        if self._closing:
            return
        if not self.active or self.busy or self._health_check_running:
            QTimer.singleShot(HEALTH_CHECK_INTERVAL_MS, self._health_tick)
            return

        self._health_check_running = True

        def worker() -> None:
            healthy = False
            ip = ""
            detail = ""
            try:
                tor = self.tor
                bridge = self.bridge
                if tor is None or not tor.running:
                    detail = "Tor process is not running"
                elif bridge is None or not bridge.running:
                    detail = "Local proxy bridge is not running"
                else:
                    is_tor, ip = check_tor(self.settings.http_proxy_port, timeout=15)
                    healthy = is_tor
                    if not healthy:
                        detail = "Health endpoint did not recognize the connection as Tor"
            except Exception as exc:
                detail = str(exc)
            self.dispatch(
                lambda healthy=healthy, ip=ip, detail=detail: self._finish_health_check(
                    healthy, ip, detail
                )
            )

        threading.Thread(target=worker, daemon=True).start()

    def _finish_health_check(self, healthy: bool, ip: str, detail: str) -> None:
        self._health_check_running = False
        if not self.active or self.busy or self._closing:
            if not self._closing:
                QTimer.singleShot(HEALTH_CHECK_INTERVAL_MS, self._health_tick)
            return

        if healthy:
            if self._health_failures:
                self.log("Automatic connection check recovered without a restart.")
            self._health_failures = 0
            if ip:
                self.ip_label.setText(f"Tor IP: {ip}")
            QTimer.singleShot(HEALTH_CHECK_INTERVAL_MS, self._health_tick)
            return

        self._health_failures += 1
        self.log(
            f"Connection health check failed "
            f"({self._health_failures}/{HEALTH_FAILURE_LIMIT}): {detail}"
        )
        if self._health_failures < HEALTH_FAILURE_LIMIT:
            QTimer.singleShot(HEALTH_RETRY_INTERVAL_MS, self._health_tick)
            return

        self._health_failures = 0
        self.log("Automatic recovery is restarting and verifying the Tor connection.")
        QTimer.singleShot(HEALTH_CHECK_INTERVAL_MS, self._health_tick)
        self._run_worker(self._refresh_connection)

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if (
            not self._closing
            and event.type() == QEvent.Type.WindowStateChange
            and self.isMinimized()
        ):
            QTimer.singleShot(0, self.hide)
            self._show_tray_hint()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._closing:
            event.accept()
            return
        if QSystemTrayIcon.isSystemTrayAvailable():
            event.ignore()
            self.hide()
            self._show_tray_hint()
        else:
            event.ignore()
            self.request_exit()

    def _show_tray_hint(self) -> None:
        if self._tray_hint_shown:
            return
        self._tray_hint_shown = True
        self.tray.showMessage(
            "AnonSurf Safe is still running",
            "Use the notification-area icon to reopen, refresh, disable, or exit.",
            QSystemTrayIcon.MessageIcon.Information,
            3500,
        )

    def request_exit(self) -> None:
        if self._exit_requested:
            return
        self._exit_requested = True
        self.hide()
        if self.busy:
            self.log("Exit requested; waiting for the current operation to finish safely.")
            return
        if self.active:
            self._run_worker(self.disable)
        else:
            self._finalize_exit()

    def _finalize_exit(self) -> None:
        self._closing = True
        self.tray.hide()
        QApplication.instance().quit()

    def _best_effort_cleanup(self) -> None:
        try:
            restore_backup()
        except Exception:
            pass
        try:
            if self.bridge:
                self.bridge.stop()
        except Exception:
            pass
        try:
            if self.tor:
                self.tor.stop()
        except Exception:
            pass


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AnonSurf Safe")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--restore-proxy",
        action="store_true",
        help="restore a saved proxy configuration",
    )
    group.add_argument(
        "--force-disable-proxy",
        action="store_true",
        help="disable the Windows manual proxy",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = _parse_args(sys.argv[1:])
    if os.name != "nt":
        print("AnonSurf Safe is a Windows-only application.")
        return

    if args.restore_proxy:
        if restore_backup():
            print("Restored the saved Windows proxy configuration.")
        else:
            print("No saved proxy configuration was found.")
        return

    if args.force_disable_proxy:
        force_disable_proxy()
        print("Disabled the Windows manual proxy.")
        return

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("AnonSurf Safe")
    qt_app.setApplicationDisplayName("AnonSurf Safe")
    qt_app.setQuitOnLastWindowClosed(False)
    qt_app.setStyle("Fusion")
    qt_app.setStyleSheet(STYLE_SHEET)
    window = AppWindow()
    qt_app.aboutToQuit.connect(window._best_effort_cleanup)
    window.show()
    sys.exit(qt_app.exec())
