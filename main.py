import os
import platform
import shlex
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QCheckBox, QGridLayout, QMessageBox,
    QTabWidget, QFileDialog, QComboBox, QListWidget, QListWidgetItem, QSplitter
)

DB_PATH = os.path.join(os.path.dirname(__file__), "nsec_toolkit_expert.db")


# -------------------- DB / Audit --------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        action TEXT,
        command TEXT,
        target TEXT,
        mode TEXT,
        container INTEGER,
        timestamp TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id INTEGER,
        tool TEXT,
        target TEXT,
        raw_args TEXT,
        return_code INTEGER,
        output TEXT,
        created_at TEXT,
        FOREIGN KEY(audit_id) REFERENCES audit(id)
    )""")
    conn.commit()
    conn.close()


def record_audit(username, email, action, command, target, mode, container):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO audit (username, email, action, command, target, mode, container, timestamp) VALUES (?,?,?,?,?,?,?,?)",
        (username, email, action, command, target, mode, int(bool(container)), ts))
    aid = cur.lastrowid
    conn.commit()
    conn.close()
    return aid


def record_scan(audit_id, tool, target, raw_args, rc, output):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO scans (audit_id, tool, target, raw_args, return_code, output, created_at) VALUES (?,?,?,?,?,?,?)",
        (audit_id, tool, target, raw_args, rc, output, ts))
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid


def list_history():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""SELECT s.id, a.username, a.email, s.tool, s.target, s.created_at, s.return_code
                   FROM scans s JOIN audit a ON s.audit_id=a.id ORDER BY s.created_at DESC""")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_scan_output(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT s.output, s.raw_args, a.username, a.email, s.return_code, s.created_at FROM scans s JOIN audit a ON s.audit_id=a.id WHERE s.id=?",
        (scan_id,))
    r = cur.fetchone()
    conn.close()
    return r


# -------------------- Worker --------------------

class CommandWorker(QThread):
    progress = Signal(str)
    finished = Signal(int, str, str)  # rc, stdout, stderr

    def __init__(self, args, name):
        super().__init__()
        self.args = args
        self.name = name
        self.proc = None

    def run(self):
        try:
            self.progress.emit(f"اجرای: {' '.join(shlex.quote(a) for a in self.args)}")
            self.proc = subprocess.Popen(self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = self.proc.communicate()
            rc = self.proc.returncode
            self.finished.emit(rc, stdout or "", stderr or "")
        except Exception as e:
            self.finished.emit(1, "", str(e))

    def stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
        except Exception:
            pass


# -------------------- Utilities --------------------

def find_runtime():
    p = shutil.which('podman') or shutil.which('docker')
    return p


def which_or_none(cmd):
    return shutil.which(cmd)


def safe_shlex_split(s):
    try:
        return shlex.split(s)
    except Exception:
        return [s]


def looks_like_flag_injection(target):
    return target.strip().startswith('-')


# --------- OS detection ---------

SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"


def resolve_tool_name(logical_name):
    if IS_WINDOWS and logical_name == 'traceroute':
        return 'tracert'
    return logical_name


def missing_tool_hint(logical_name, resolved_binary):

    if which_or_none(resolved_binary):
        return None
    if IS_WINDOWS:
        hints = {
            'whois': "'winget install Microsoft.Sysinternals' را اجرا کن. دستور whois به‌صورت پیش‌فرض روی ویندوز نصب نیست.",
            'dig': "دستور 'nslookup' (جایگزین dig روی ویندوز) پیدا نشد؛ این ابزار معمولاً به‌صورت پیش‌فرض روی ویندوز نصب است. برای dig واقعی: 'winget install ISC.BIND'.",
            'nmap': "'winget install Insecure.Nmap' را اجرا کن. دستور nmap به‌صورت پیش‌فرض روی ویندوز نصب نیست.",
            'traceroute': "دستور 'tracert' (جایگزین traceroute روی ویندوز) پیدا نشد. این ابزار معمولاً به‌صورت پیش‌فرض روی ویندوز موجود است.",
        }
    else:
        hints = {
            'whois': "نصب نیست. با 'sudo apt install whois' (یا معادلش در توزیعت) نصبش کن.",
            'dig': "نصب نیست. با 'sudo apt install dnsutils' (یا bind-utils) نصبش کن.",
            'nmap': "نصب نیست. با 'sudo apt install nmap' نصبش کن.",
            'traceroute': "نصب نیست. با 'sudo apt install traceroute' (یا معادلش در توزیعت) نصبش کن.",
        }
    return hints.get(logical_name, f"دستور '{resolved_binary}' روی PATH پیدا نشد.")


def build_command(tool_name, target=None, options=None):
    options = options or {}

    if tool_name == 'nmap':

        binary = which_or_none('nmap') or 'nmap'
        extra = list(options.get('args', []))
        cmd = [binary] + extra
        if target and target not in extra:
            cmd.append(target)
        return cmd

    if tool_name == 'ping':
        binary = which_or_none('ping') or 'ping'
        count = str(options.get('count', 4))
        count_flag = '-n' if IS_WINDOWS else '-c'
        return [binary, count_flag, count, target]

    if tool_name == 'traceroute':
        logical = resolve_tool_name('traceroute')
        binary = which_or_none(logical) or logical
        return [binary, target]

    if tool_name == 'dig':
        if IS_WINDOWS:
            binary = which_or_none('nslookup') or 'nslookup'
            rtype = options.get('record_type')
            args = [binary]
            if rtype:
                args.append('-type=' + rtype)
            args.append(target)
            return args
        binary = which_or_none('dig') or 'dig'
        args = [binary, target]
        rtype = options.get('record_type')
        if rtype:
            args.append(rtype)
        return args

    if tool_name == 'whois':
        binary = which_or_none('whois') or 'whois'
        return [binary, target]

    if tool_name == 'arp':
        binary = which_or_none('arp') or 'arp'

        flag = '-a' if IS_WINDOWS else '-n'
        return [binary, flag]

    if tool_name == 'ip':
        if IS_WINDOWS:
            binary = which_or_none('ipconfig') or 'ipconfig'
            return [binary, '/all']
        binary = which_or_none('ip') or 'ip'
        return [binary, 'a']

    if tool_name == 'route':

        if IS_WINDOWS:
            binary = which_or_none('route') or 'route'
            return [binary, 'print']
        binary = which_or_none('ip') or 'ip'
        return [binary, 'route']

    if tool_name == 'hostname':
        binary = which_or_none('hostname') or 'hostname'
        return [binary]

    if tool_name == 'netstat':
        if IS_WINDOWS:
            binary = which_or_none('netstat') or 'netstat'
            return [binary, '-ano']
        binary = which_or_none('ss') or 'ss'
        return [binary, '-tunap']

    raise ValueError(f"Unknown tool_name for build_command: {tool_name!r}")



def build_ping_args(target, count):
    return build_command('ping', target, {'count': count})


def build_traceroute_args(target):
    return build_command('traceroute', target)


def build_arp_args():
    return build_command('arp')


def build_ip_info_args():
    return build_command('ip')


def build_socket_stats_args():
    return build_command('netstat')


def build_route_args():
    return build_command('route')


def build_hostname_args():
    return build_command('hostname')


# -------------------- GUI --------------------

class MainApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Safe-net")
        self.resize(1200, 750)
        self.setLayoutDirection(Qt.RightToLeft)  # UI labels are Persian
        self.workers = []
        self.current_audit_id = None
        self._build_ui()
        init_db()
        self.refresh_history()

    def _build_ui(self):
        main = QVBoxLayout()
        # --- user info (required for audit) ---
        user_row = QHBoxLayout()
        user_row.addWidget(QLabel(":نام مهندس"))
        self.user_name = QLineEdit()
        self.user_name.setPlaceholderText("مثلاً: mahdi")
        user_row.addWidget(self.user_name)
        user_row.addWidget(QLabel(":ایمیل"))
        self.user_email = QLineEdit()
        self.user_email.setPlaceholderText("مثلاً: you@gmail.com")
        user_row.addWidget(self.user_email)
        self.container_chk = QCheckBox("Run in container if available (podman/docker)")
        self.container_chk.setToolTip(
            "در حال حاضر فقط برای اسکن Nmap اعمال می‌شود، چون ایمیج نمونه فقط شامل nmap است.")
        user_row.addWidget(self.container_chk)
        main.addLayout(user_row)

        # --- target input ---
        top = QHBoxLayout()
        top.addWidget(QLabel("Target (IP/CIDR or hostname):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("مثال: 192.168.1.0/24 یا example.com")
        top.addWidget(self.target_input)
        load_btn = QPushButton("Load from file")
        load_btn.clicked.connect(self.load_targets_file)
        top.addWidget(load_btn)
        main.addLayout(top)

        # --- tabs ---
        self.tabs = QTabWidget()
        self.tabs.addTab(self._nmap_tab(), "Nmap")
        self.tabs.addTab(self._nettools_tab(), "Network Tools")
        self.tabs.addTab(self._dnswhois_tab(), "DNS & Whois")
        self.tabs.addTab(self._local_tab(), "Local Info")
        self.tabs.addTab(self._advanced_tab(), "Advanced (Raw)")
        main.addWidget(self.tabs)

        # preview & controls
        self.preview = QLineEdit()
        self.preview.setReadOnly(True)
        main.addWidget(QLabel("Command preview:"))
        main.addWidget(self.preview)

        btn_row = QHBoxLayout()
        self.run_btn = QPushButton("Run Selected (Expert)")
        self.run_btn.clicked.connect(self.run_selected)
        self.cancel_btn = QPushButton("Cancel All")
        self.cancel_btn.clicked.connect(self.cancel_all)
        self.refresh_btn = QPushButton("Refresh History")
        self.refresh_btn.clicked.connect(self.refresh_history)
        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.refresh_btn)
        main.addLayout(btn_row)

        splitter = QSplitter(Qt.Horizontal)
        left_w = QWidget()
        left_layout = QVBoxLayout()
        left_w.setLayout(left_layout)
        left_layout.addWidget(QLabel("History (scans)"))
        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.on_history_click)
        left_layout.addWidget(self.history_list)
        # right: console / output
        right_w = QWidget()
        right_layout = QVBoxLayout()
        right_w.setLayout(right_layout)
        right_layout.addWidget(QLabel("Console Output"))
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        right_layout.addWidget(self.console)
        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        main.addWidget(splitter, stretch=1)

        self.setLayout(main)

    # ------------- tabs content -------------
    def _nmap_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        g = QGridLayout()
        self.cb_top100 = QCheckBox("Top 100 ports")
        self.cb_syn = QCheckBox("TCP SYN (-sS)")
        self.cb_connect = QCheckBox("TCP Connect (-sT)")
        self.cb_udp = QCheckBox("UDP (-sU)")
        self.cb_os = QCheckBox("OS detect (-O)")
        self.cb_service = QCheckBox("Service/version (-sV)")
        self.cb_aggr = QCheckBox("Aggressive (-A)")
        self.cb_ping = QCheckBox("Ping only (-sn)")
        self.port_input = QLineEdit()
        self.scripts_input = QLineEdit()
        self.timing_combo = QComboBox()
        self.timing_combo.addItems(['0', '1', '2', '3', '4', '5'])
        self.timing_combo.setCurrentIndex(3)  # default T3, nmap's own default
        g.addWidget(self.cb_top100, 0, 0)
        g.addWidget(self.cb_syn, 0, 1)
        g.addWidget(self.cb_connect, 1, 0)
        g.addWidget(self.cb_udp, 1, 1)
        g.addWidget(self.cb_os, 2, 0)
        g.addWidget(self.cb_service, 2, 1)
        g.addWidget(self.cb_aggr, 3, 0)
        g.addWidget(self.cb_ping, 3, 1)
        g.addWidget(QLabel("Ports:"), 4, 0)
        g.addWidget(self.port_input, 4, 1)
        g.addWidget(QLabel("Scripts (comma):"), 5, 0)
        g.addWidget(self.scripts_input, 5, 1)
        g.addWidget(QLabel("Timing T:"), 6, 0)
        g.addWidget(self.timing_combo, 6, 1)
        layout.addLayout(g)
        w.setLayout(layout)
        return w

    def _nettools_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        h = QHBoxLayout()
        self.cb_ping_tool = QCheckBox("Ping")
        self.ping_count = QLineEdit("3")
        self.ping_count.setFixedWidth(60)
        self.cb_traceroute = QCheckBox("Traceroute")
        h.addWidget(self.cb_ping_tool)
        h.addWidget(QLabel("Count:"))
        h.addWidget(self.ping_count)
        h.addWidget(self.cb_traceroute)
        layout.addLayout(h)
        w.setLayout(layout)
        return w

    def _dnswhois_tab(self):
        w = QWidget()
        layout = QHBoxLayout()
        self.cb_whois = QCheckBox("Whois")
        self.cb_dig = QCheckBox("Dig")
        self.dig_type = QComboBox()
        self.dig_type.addItems(['A', 'AAAA', 'MX', 'NS', 'TXT'])
        layout.addWidget(self.cb_whois)
        layout.addWidget(self.cb_dig)
        layout.addWidget(QLabel("Type:"))
        layout.addWidget(self.dig_type)
        w.setLayout(layout)
        return w

    def _local_tab(self):
        w = QWidget()
        layout = QHBoxLayout()
        self.cb_arp = QCheckBox("ARP Table")
        self.cb_ip = QCheckBox("IP Configuration")
        self.cb_ss = QCheckBox("Active Connections")
        layout.addWidget(self.cb_arp)
        layout.addWidget(self.cb_ip)
        layout.addWidget(self.cb_ss)
        w.setLayout(layout)
        return w

    def _advanced_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Advanced / Raw Arguments — (Expert mode: unrestricted)"))
        self.raw_tool = QComboBox()
        self.raw_tool.addItems(['nmap', 'ping', 'traceroute', 'whois', 'dig', 'custom'])
        self.raw_args = QLineEdit()
        self.raw_args.setPlaceholderText("مثال برای nmap: -sS -p 22,80 --script vuln")
        layout.addWidget(QLabel("Tool:"))
        layout.addWidget(self.raw_tool)
        layout.addWidget(QLabel("Raw args (will be used as-is):"))
        layout.addWidget(self.raw_args)
        w.setLayout(layout)
        return w

    # ------------- nmap arg helpers (shared by preview + execution) -------------
    def _nmap_enabled(self):
        return any([
            self.cb_top100.isChecked(), self.cb_syn.isChecked(), self.cb_connect.isChecked(),
            self.cb_udp.isChecked(), self.cb_os.isChecked(), self.cb_service.isChecked(),
            self.cb_aggr.isChecked(), self.cb_ping.isChecked(), self.port_input.text().strip(),
            self.scripts_input.text().strip()
        ])

    def _collect_nmap_option_args(self):
        args = []
        if self.cb_top100.isChecked(): args += ['--top-ports', '100']
        if self.cb_syn.isChecked(): args += ['-sS']
        if self.cb_connect.isChecked(): args += ['-sT']
        if self.cb_udp.isChecked(): args += ['-sU']
        if self.cb_os.isChecked(): args += ['-O']
        if self.cb_service.isChecked(): args += ['-sV']
        if self.cb_aggr.isChecked(): args += ['-A']
        if self.cb_ping.isChecked(): args += ['-sn']
        if self.port_input.text().strip(): args += ['-p', self.port_input.text().strip()]
        if self.scripts_input.text().strip(): args += ['--script', self.scripts_input.text().strip()]
        args += ['-T' + self.timing_combo.currentText()]
        args += ['-oX', '-']
        return args

    # ------------- actions -------------
    def load_targets_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load targets", ".", "Text files (*.txt);;All files (*)")
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip()]
                if lines:
                    self.target_input.setText(lines[0])
                    QMessageBox.information(self, "Loaded", f"{len(lines)} targets loaded (MVP: uses first).")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"خطا: {e}")

    def aggregate_preview(self):
        t = self.target_input.text().strip() or "<target>"
        parts = []
        if self._nmap_enabled():
            nmap_opts = self._collect_nmap_option_args()
            full_args = build_command('nmap', t, {'args': nmap_opts})
            parts.append(" ".join(shlex.quote(a) for a in full_args))
        if self.cb_ping_tool.isChecked():
            cnt_text = self.ping_count.text().strip() or "3"
            parts.append(" ".join(build_command('ping', t, {'count': cnt_text})))
        if self.cb_traceroute.isChecked():
            parts.append(" ".join(build_command('traceroute', t)))
        if self.cb_whois.isChecked():
            parts.append(" ".join(build_command('whois', t)))
        if self.cb_dig.isChecked():
            parts.append(" ".join(build_command('dig', t, {'record_type': self.dig_type.currentText()})))
        local_parts = []
        if self.cb_arp.isChecked(): local_parts.append(" ".join(build_command('arp')))
        if self.cb_ip.isChecked(): local_parts.append(" ".join(build_command('ip')))
        if self.cb_ss.isChecked(): local_parts.append(" ".join(build_command('netstat')))
        if local_parts:
            parts.append(" ; ".join(local_parts))
        # raw
        if self.raw_args.text().strip():
            rt = self.raw_tool.currentText()
            parts.append(f"RAW({rt}) {self.raw_args.text().strip()}")
        self.preview.setText(" || ".join(parts))

    def run_selected(self):
        # check user info present
        uname = self.user_name.text().strip()
        uemail = self.user_email.text().strip()
        if not uname or not uemail:
            QMessageBox.warning(self, "اطلاعات کاربر لازم است", "برای ثبت لاگ و مسئولیت، نام و ایمیل خود را وارد کنید.")
            return

        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target required", "ابتدا target را وارد کنید.")
            return
        if looks_like_flag_injection(target):
            QMessageBox.warning(
                self, "Target نامعتبر",
                "مقدار target با '-' شروع می‌شود و ممکن است توسط ابزارها به‌عنوان یک "
                "فلگ خط‌فرمان تفسیر شود، نه به‌عنوان هدف. لطفاً مقدار را اصلاح کنید.")
            return

        container_runtime = find_runtime() if self.container_chk.isChecked() else None
        full_command_summary = self.preview.text() or "manual"
        aid = record_audit(uname, uemail, "RUN_BATCH", full_command_summary, target, "EXPERT", bool(container_runtime))
        self.current_audit_id = aid


        if self._nmap_enabled():

            hint = None if container_runtime else missing_tool_hint('nmap', 'nmap')
            if hint:
                self._report_missing_tool("nmap", aid, target, hint)
            else:
                nmap_opts = self._collect_nmap_option_args()
                args = build_command('nmap', target, {'args': nmap_opts})
                # nmap is the only tool with a matching container image, so it's
                # the only one allowed to use container_runtime
                self._run_tool_thread("nmap", args, aid, target, " ".join(args), container_runtime)

        # Ping
        if self.cb_ping_tool.isChecked():
            hint = missing_tool_hint('ping', 'ping')
            if hint:
                self._report_missing_tool("ping", aid, target, hint)
            else:
                try:
                    cnt = int(self.ping_count.text().strip())
                except ValueError:
                    cnt = 3
                args = build_command('ping', target, {'count': cnt})
                self._run_tool_thread("ping", args, aid, target, " ".join(args), None)

        if self.cb_traceroute.isChecked():
            resolved = resolve_tool_name('traceroute')
            hint = missing_tool_hint('traceroute', resolved)
            if hint:
                self._report_missing_tool("traceroute", aid, target, hint)
            else:
                args = build_command('traceroute', target)
                self._run_tool_thread("traceroute", args, aid, target, " ".join(args), None)

        if self.cb_whois.isChecked():
            hint = missing_tool_hint('whois', 'whois')
            if hint:
                self._report_missing_tool("whois", aid, target, hint)
            else:
                args = build_command('whois', target)
                self._run_tool_thread("whois", args, aid, target, " ".join(args), None)

        if self.cb_dig.isChecked():
            dig_resolved = 'nslookup' if IS_WINDOWS else 'dig'
            hint = missing_tool_hint('dig', dig_resolved)
            if hint:
                self._report_missing_tool("dig", aid, target, hint)
            else:
                q = self.dig_type.currentText()
                args = build_command('dig', target, {'record_type': q})
                self._run_tool_thread("dig", args, aid, target, " ".join(args), None)

        # local tools
        if self.cb_arp.isChecked():
            arp_resolved = 'arp'
            hint = missing_tool_hint('arp', arp_resolved)
            if hint:
                self._report_missing_tool("arp", aid, target, hint)
            else:
                args = build_command('arp')
                self._run_tool_thread("arp", args, aid, target, " ".join(args), None)
        if self.cb_ip.isChecked():
            ip_resolved = 'ipconfig' if IS_WINDOWS else 'ip'
            hint = missing_tool_hint('ip', ip_resolved)
            if hint:
                self._report_missing_tool("ip", aid, target, hint)
            else:
                args = build_command('ip')
                self._run_tool_thread("ip", args, aid, target, " ".join(args), None)
        if self.cb_ss.isChecked():
            ss_resolved = 'netstat' if IS_WINDOWS else 'ss'
            hint = missing_tool_hint('ss', ss_resolved)
            if hint:
                self._report_missing_tool("ss", aid, target, hint)
            else:
                args = build_command('netstat')
                self._run_tool_thread("ss", args, aid, target, " ".join(args), None)

        # raw / advanced: UNRESTRICTED — expert mode.
        # Since this can run literally anything the user typed, ask for an
        # explicit confirmation before firing it off.
        raw_text = self.raw_args.text().strip()
        if raw_text:
            reply = QMessageBox.question(
                self, "تایید اجرای دستور Expert",
                "دستور زیر بدون هیچ محدودیت یا بررسی امنیتی اجرا خواهد شد:\n\n"
                f"{raw_text}\n\nمطمئن هستید؟",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                rt = self.raw_tool.currentText()
                toks = safe_shlex_split(raw_text)
                if rt == 'custom':
                    args = toks
                    raw_container = None
                    self._run_tool_thread(f"raw:{rt}", args, aid, target, " ".join(args), raw_container)
                else:
                    real_name = resolve_tool_name(rt)
                    cmd_path = which_or_none(real_name) or real_name
                    raw_container = container_runtime if rt == 'nmap' else None

                    hint = None if raw_container else missing_tool_hint(rt, real_name)
                    if hint:
                        self._report_missing_tool(f"raw:{rt}", aid, target, hint)
                    else:
                        args = [cmd_path] + toks
                        if rt == 'nmap' and target not in toks:
                            args = args + [target]
                        self._run_tool_thread(f"raw:{rt}", args, aid, target, " ".join(args), raw_container)

        self.aggregate_preview()
        self.refresh_history()

    def _run_tool_thread(self, tool_name, args, audit_id, target, raw_cmd_str, container_runtime):
        if container_runtime:
            runtime = container_runtime
            image = "nmaptools:latest"
            run_in_container = False
            if shutil.which(runtime):
                img_check = subprocess.run([runtime, "images", "-q", image], capture_output=True, text=True)
                if img_check.returncode == 0 and img_check.stdout.strip():
                    run_in_container = True
            if run_in_container:
                container_cmd = [runtime, "run", "--rm", "--network", "host", image] + args
                final_args = container_cmd
            else:
                final_args = args
        else:
            final_args = args

        # spawn thread
        w = CommandWorker(final_args, tool_name)
        w.progress.connect(self.on_progress)

        def finish_cb(rc, stdout, stderr):
            out = stdout or ""
            if stderr:
                out += ("\n[stderr]\n" + stderr)
            record_scan(audit_id, tool_name, target, raw_cmd_str, rc, out)
            self.on_finished(tool_name, rc, out)
            if w in self.workers:
                self.workers.remove(w)

        w.finished.connect(lambda rc, so, se: finish_cb(rc, so, se))
        w.start()
        self.workers.append(w)
        item = QListWidgetItem(f"{datetime.utcnow().isoformat()}  {tool_name}  target={target}")
        self.history_list.insertItem(0, item)

    def _report_missing_tool(self, tool_name, audit_id, target, hint):
        msg = f"ابزار '{tool_name}' روی این سیستم پیدا نشد.\n{hint}"
        record_scan(audit_id, tool_name, target, "", 127, msg)
        self.on_finished(tool_name, 127, msg)
        item = QListWidgetItem(
            f"{datetime.utcnow().isoformat()}  {tool_name}  target={target}  [missing]")
        self.history_list.insertItem(0, item)

    def on_progress(self, s):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{ts}] {s}")

    def on_finished(self, tool_name, rc, out):
        ts = datetime.now().strftime("%H:%M:%S")
        header = f"\n=== [{ts}] {tool_name} finished (rc={rc}) ===\n"
        self.console.append(header + out + "\n")

    def cancel_all(self):
        for w in self.workers:
            try:
                w.stop()
            except Exception:
                pass
        self.workers = []
        self.console.append("[User cancelled all jobs]\n")

    # ------------- history -------------
    def refresh_history(self):
        self.history_list.clear()
        rows = list_history()
        for r in rows:
            sid, uname, email, tool, target, created_at, rc = r
            it = QListWidgetItem(f"{sid} | {created_at} | {tool} | {target} | rc={rc} | {uname}")
            it.setData(Qt.UserRole, sid)
            self.history_list.addItem(it)

    def on_history_click(self, item):
        sid = item.data(Qt.UserRole)
        data = get_scan_output(sid)
        if not data:
            QMessageBox.information(self, "No data", "Record not found")
            return
        output, raw_args, uname, email, rc, created_at = data
        dlg = QMessageBox(self)
        dlg.setWindowTitle(f"Scan {sid} — details")
        dlg.setText(
            f"User: {uname} <{email}>\nTime: {created_at}\nReturn code: {rc}\n\nRaw args: {raw_args}\n\nOutput (truncated):\n{output[:4000]}")
        dlg.exec()

    def closeEvent(self, event):
        if self.workers:
            if QMessageBox.question(self, "Exit", "برنامه در حال اجرا است مطمئنی می‌خوای خارج شی؟",
                                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                event.ignore()
                return
        event.accept()


# -------------------- Main --------------------
def main():
    app = QApplication(sys.argv)
    win = MainApp()

    # wire inputs to preview
    widgets = [
        win.target_input, win.cb_top100, win.cb_syn, win.cb_connect, win.cb_udp, win.cb_os, win.cb_service,
        win.cb_aggr, win.cb_ping, win.port_input, win.scripts_input, win.timing_combo, win.cb_ping_tool,
        win.ping_count, win.cb_traceroute, win.cb_whois, win.cb_dig, win.dig_type,
        win.cb_arp, win.cb_ip, win.cb_ss, win.raw_tool, win.raw_args
    ]
    for w in widgets:
        try:
            w.textChanged.connect(win.aggregate_preview)
        except Exception:
            try:
                w.stateChanged.connect(win.aggregate_preview)
            except Exception:
                try:
                    w.currentIndexChanged.connect(win.aggregate_preview)
                except Exception:
                    pass
    win.aggregate_preview()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()