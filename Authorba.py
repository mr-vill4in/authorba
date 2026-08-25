# -*- coding: utf-8 -*-
"""
Authorba - Broken Access Control testing extension for Burp Suite.

Tests BOLA (object-level), BFLA (function-level) and BOPLA (property-level)
authorization issues by replaying captured requests under multiple user
identities across roles, and comparing results against a role-permission
matrix.

Requirements: Burp Suite + Jython (Standalone) JAR loaded as Python environment.
Load via Extender -> Add -> Extension Type: Python.

Author: Mr_Vill4in
License: MIT
"""

import re
import json
import base64
import random
import string
import thread
import time
import traceback
from java.awt import BorderLayout, Color, Dimension, Font, GridLayout, FlowLayout
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JButton, JLabel, JTextField, JTable, JScrollPane,
    JComboBox, JCheckBox, JDialog, BoxLayout, BorderFactory, JOptionPane,
    ListSelectionModel, SwingUtilities, JProgressBar, JFileChooser, JTextArea,
    JScrollPane, JSplitPane, DefaultComboBoxModel, JList, DefaultListModel,
    Box, JMenuBar, JMenu, JMenuItem, UIManager, JPopupMenu, JMenuItem as JSep,
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, TableModelListener
from burp import IBurpExtender, IProxyListener, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory

TAG = "Authorba"


def log(msg):
    print("[%s] %s" % (TAG, msg))


# ---------------------------------------------------------------------------
# Static asset / noise filtering
# ---------------------------------------------------------------------------

STATIC_EXT_RE = re.compile(
    r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|bmp|webp|woff2?|ttf|eot|mp4|webm|"
    r"mp3|wav|pdf|zip|gz|tgz|rar|7z|txt|xml|font|swf)(\?|$)", re.IGNORECASE)

STATIC_PATH_RE = re.compile(
    r"^/?(favicon\.ico|robots\.txt|sitemap\.xml|apple-touch-icon[^/]*)$", re.IGNORECASE)

CSRF_NAME_RE = re.compile(
    r"(csrf|xsrf|authenticity[_-]?token|_token|request[_-]?token|anti[_-]?forgery|nonce)", re.I)

AUTH_HEADER_RE = re.compile(
    r"^(authorization|cookie|x-api-key|x-auth-token|x-access-token|x-session-token|"
    r"api-key|apikey|x-csrf-token|x-xsrf-token)$", re.I)

BEARER_RE = re.compile(r"^\s*Bearer\s+(.+)$", re.I)

DYNAMIC_TOKEN_RE = re.compile(
    r"\b[0-9a-f]{8,}-?[0-9a-f]{4,}\b|\b\d{10,13}\b", re.I)


def is_static_asset(path):
    return bool(STATIC_EXT_RE.search(path) or STATIC_PATH_RE.match(path))


# ---------------------------------------------------------------------------
# Endpoint normalization: /api/orders/1001 -> /api/orders/{id}
# ---------------------------------------------------------------------------

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEXID_RE = re.compile(r"^[0-9a-fA-F]{12,}$")


def normalize_path(path):
    """Template volatile ID segments so /users/2 and /users/99 dedupe."""
    base = path.split("?")[0]
    out = []
    for seg in base.split("/"):
        if UUID_RE.match(seg) or HEXID_RE.match(seg) or seg.isdigit():
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def path_id_values(path):
    """Return [(resource, value)] for each volatile ID segment, e.g.
    /api/orders/1001 -> [("orders", "1001")]. Used for object-swap BOLA."""
    base = path.split("?")[0]
    segs = base.split("/")
    found = []
    for i, seg in enumerate(segs):
        if (UUID_RE.match(seg) or HEXID_RE.match(seg) or seg.isdigit()) and i > 0 \
                and segs[i - 1] and segs[i - 1] != "{id}":
            found.append((segs[i - 1], seg))
    return found


def graphql_operation_key(request):
    """Key a GraphQL endpoint by operation type + name instead of path."""
    body = request.partition("\r\n\r\n")[2]
    m = re.search(r"\b(query|mutation|subscription)\s*([A-Za-z_][\w]*)?", body or "")
    if not m:
        return "graphql"
    return "graphql:%s:%s" % (m.group(1), m.group(2) or "-")


def normalize_body(body):
    """Mask volatile values (timestamps, uuids, nonces, long hex) so responses
    can be compared without noise."""
    if not body:
        return ""
    b = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", "<TS>", body)
    b = DYNAMIC_TOKEN_RE.sub("<DYN>", b)
    b = re.sub(r"\b\d{7,}\b", "<NUM>", b)
    return b


def body_similarity(a, b):
    """Rough similarity (0.0-1.0) of two response bodies after masking."""
    na, nb = normalize_body(a), normalize_body(b)
    if na == nb:
        return 1.0
    sa = set(re.findall(r"\w+", na))
    sb = set(re.findall(r"\w+", nb))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return float(inter) / float(max(len(sa), len(sb)))


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def jwt_decode(token):
    """Return (header_dict, payload_dict, error) for a JWT string."""
    try:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return None, None, "not a JWT (needs >= 2 dot-separated parts)"
        def dec(seg):
            seg = seg.strip()
            pad = "=" * (-len(seg) % 4)
            raw = base64.urlsafe_b64decode(seg + pad)
            return json.loads(raw)
        return dec(parts[0]), dec(parts[1]), None
    except Exception as e:
        return None, None, str(e)


def jwt_summary(token):
    hdr, pl, err = jwt_decode(token)
    if err:
        return "JWT decode error: %s" % err
    flags = []
    alg = (hdr or {}).get("alg", "")
    if alg in ("none", "", None):
        flags.append("!! alg is 'none'/absent - unsigned token, trivially forgeable")
    if token.count(".") < 3 or not token.split(".")[2]:
        flags.append("!! empty signature")
    for k in ("jku", "jwk", "x5u", "x5c", "kid"):
        if k in (hdr or {}):
            flags.append("? header '%s' present - check for injection/SSRF "
                         "(try path traversal / attacker-hosted keys in kid/jku)" % k)
    if pl and "exp" not in pl:
        flags.append("? no exp claim - token may never expire")
    out = ["=== JWT HEADER ===", json.dumps(hdr, indent=2, sort_keys=True),
           "=== JWT PAYLOAD ==="]
    if pl:
        out.append(json.dumps(pl, indent=2, sort_keys=True))
        if "exp" in pl and isinstance(pl["exp"], (int, long, float)):
            age = time.time() - pl["exp"]
            if age > 0:
                flags.append("!! EXPIRED %.1f minutes ago (replay may still work "
                             "if server doesn't validate exp)" % (age / 60.0))
            else:
                out.append("exp epoch: %s (valid for %.0f more minutes)" % (
                    pl["exp"], -age / 60.0))
    if flags:
        out.append("=== FLAGS ===")
        out.extend(flags)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Endpoint(object):
    """A captured request treated as a testable endpoint."""
    _next_id = [1]

    def __init__(self, method, path, host, port, ssl, request_bytes):
        self.id = Endpoint._next_id[0]
        Endpoint._next_id[0] += 1
        self.method = method
        self.path = path          # full path incl. query
        self.host = host
        self.port = port
        self.ssl = bool(ssl)
        self.request = request_bytes  # str (latin-1 safe)
        self.endpoint_key = normalize_path(path)
        self.graphql = self._detect_graphql()
        if self.graphql:
            self.endpoint_key = graphql_operation_key(request_bytes)
        self.write_allowed = False   # non-GET replays need explicit opt-in
        self.notes = ""

    def _detect_graphql(self):
        if re.search(r"/graphql($|[/?])", self.path, re.I):
            return True
        head, _, body = self.request.partition("\r\n\r\n")
        return bool(re.search(r"(query|mutation|subscription)\s*[\{\(]", body or ""))

    def label(self):
        flag = "" if self.method in ("GET", "HEAD", "OPTIONS") else (
            " [write-OK]" if self.write_allowed else " [write-blocked]")
        return "%s %s%s" % (self.method, self.path, flag)

    def category(self):
        """Heuristic BOLA / BFLA / BOPLA tagging."""
        p = self.endpoint_key.lower()
        body_head = self.request.partition("\r\n\r\n")[2][:500].lower()
        if self.graphql:
            if re.search(r"\bmutation\b", body_head):
                return "GraphQL mutation (BFLA-ish)"
            return "GraphQL query (BOLA-ish)"
        if re.search(r"/(admin|internal|private|manage|backoffice)", p):
            return "BFLA (admin function)"
        if re.search(r"\b(password|passwd|secret|token|apikey|ssn|salary|role|isAdmin|is_admin)\b",
                     body_head) or re.search(r"(password|secret|apikey|token)", p):
            return "BOPLA (sensitive property)"
        if re.search(r"/\d+|\bid=|uuid|guid", p):
            return "BOLA (object id)"
        return "generic"


class User(object):
    def __init__(self, name, role):
        self.name = name
        self.role = role
        self.cookies = {}      # {name: value} replaces Cookie header entirely
        self.headers = {}      # {name: value} set/replace on request (e.g. Authorization)
        self.enabled = True
        # session refresh
        self.refresh_request = None   # raw request str to re-login
        self.refresh_cookies_re = ""  # regex with group 1 = new session cookie value
        self.refresh_headers_re = ""  # regex with group 1 = new token (header auth)
        self.refresh_header_name = "Authorization"
        self.last_refresh = 0
        self.objects = {}   # resource -> owned object id, e.g. {"orders": "1001"}
        self.canary = ""    # string unique to this user; seeing it in ANOTHER
                            # user's response = cross-user data leak

    def to_dict(self):
        return {"name": self.name, "role": self.role, "cookies": self.cookies,
                "headers": self.headers, "enabled": self.enabled,
                "refresh_request": self.refresh_request,
                "refresh_cookies_re": self.refresh_cookies_re,
                "refresh_headers_re": self.refresh_headers_re,
                "refresh_header_name": self.refresh_header_name,
                "objects": self.objects,
                "canary": self.canary}

    @staticmethod
    def from_dict(d):
        u = User(d["name"], d["role"])
        u.cookies = d.get("cookies", {}) or {}
        u.headers = d.get("headers", {}) or {}
        u.enabled = d.get("enabled", True)
        u.refresh_request = d.get("refresh_request")
        u.refresh_cookies_re = d.get("refresh_cookies_re", "")
        u.refresh_headers_re = d.get("refresh_headers_re", "")
        u.refresh_header_name = d.get("refresh_header_name", "Authorization")
        u.objects = d.get("objects", {}) or {}
        u.canary = d.get("canary", "") or ""
        return u


# Verdicts
V_BLOCKED = "BLOCKED"          # 401/403 - access denied (good, if role not allowed)
V_ALLOWED = "ALLOWED"          # 2xx and role is permitted
V_FINDING = "FINDING"          # 2xx and role NOT permitted  <-- broken access control
V_UNVERIFIED = "UNVERIFIED"    # 2xx but no permission defined for this role
V_ERROR = "ERROR"
V_SKIPPED = "SKIPPED"
V_BOLA = "BOLA"              # cross-user object access confirmed by object-swap
V_PUBLIC = "PUBLIC"          # endpoint responds identically without any auth
V_INFRA = "WAF/RL"           # infrastructure block (WAF / rate limit), not app authz

VERDICT_COLORS = {
    V_BLOCKED: Color(0x2E, 0x7D, 0x32),   # green
    V_ALLOWED: Color(0x79, 0x9C, 0xB0),   # blue-gray
    V_FINDING: Color(0xD3, 0x2F, 0x2F),   # red
    V_UNVERIFIED: Color(0xF5, 0x7C, 0x00),# amber
    V_ERROR: Color(0x6A, 0x1B, 0x9A),     # purple
    V_SKIPPED: Color(0x9E, 0x9E, 0x9E),   # gray
    V_BOLA: Color(0xC2, 0x18, 0x5B),      # crimson
    V_PUBLIC: Color(0x02, 0x88, 0xD1),    # light blue
    V_INFRA: Color(0x7B, 0x1F, 0xA2),     # violet
    None: Color.WHITE,
}

WAF_MARKER_RE = re.compile(
    r"(?i)(rate.?limit|too many requests|request throttled|cloudflare|"
    r"captcha|access to this page has been denied|incident id|akamai)", re.I)


def looks_like_infra_block(status, body):
    """WAF / rate-limit / bot-check blocks - infrastructure, not app authz."""
    if status in (429, 503, 502):
        return True
    if status == 403 and body and WAF_MARKER_RE.search(body[:4096]):
        return True
    return False


def is_empty_success(status, body):
    """200 with an empty / empty-collection body usually means row-level
    filtering: the app 'allowed' the request but returned none of the data."""
    if not (200 <= status < 300) or not body:
        return status == 204
    stripped = body.strip()
    if stripped in ("", "{}", "[]", '""', "null", '{"data":null}', '{"data":{}}',
                    '{"data":[]}', '{"items":[]}', '{"results":[]}', '{"orders":[]}'):
        return True
    return len(stripped) < 5


def endpoint_risk_score(ep):
    """Deterministic 0-100 BOLA/IDOR likelihood score (authz-hunter style):
    prioritizes what to test first. Higher = more interesting."""
    score = 0
    base = ep.endpoint_key
    if "{id}" in base:
        score += 30                      # object reference in path
    if re.search(r"[?&][^=]*(id|uuid|guid|ref)=", ep.path, re.I):
        score += 15                      # object reference in query
    if ep.method in ("POST", "PUT", "PATCH", "DELETE"):
        score += 20                      # state-changing
    if ep.graphql:
        score += 10
    cat = ep.category()
    if cat.startswith("BOLA"):
        score += 10
    elif cat.startswith("BFLA"):
        score += 15
    elif cat.startswith("BOPLA"):
        score += 15
    # auth-required signal: original request carried auth material
    hdr_names = [h.split(":", 1)[0] for h in
                 ep.request.split("\r\n\r\n")[0].split("\r\n")[1:]]
    if any(AUTH_HEADER_RE.match(n or "") for n in hdr_names):
        score += 10
    return min(score, 100)


class Result(object):
    def __init__(self, endpoint, user):
        self.endpoint = endpoint
        self.user = user
        self.status = 0
        self.length = 0
        self.similarity = 1.0
        self.verdict = V_SKIPPED
        self.request = ""
        self.response = ""
        self.error = ""
        self.mtime = time.time()


# ---------------------------------------------------------------------------
# Request building / auth substitution
# ---------------------------------------------------------------------------

class RequestBuilder(object):
    """Rebuilds a captured request with a different identity's auth material."""

    def __init__(self, callbacks):
        self._helpers = callbacks.getHelpers()

    def parse(self, request_str):
        return self._helpers.analyzeRequest(
            self._helpers.buildHttpService("x", 80, False),
            request_str)

    def build(self, endpoint, user, csrf_value=None, csrf_target=None):
        """Return (request_str, csrf_meta or None).

        csrf_target: dict describing where the original CSRF token lives,
        {'type': 'header'|'param', 'name': ...} - it will be replaced with
        csrf_value (fresh token) if provided.
        """
        req = endpoint.request
        info = self._helpers.analyzeRequest(
            self._helpers.buildHttpService(endpoint.host, endpoint.port, endpoint.ssl), req)
        headers = list(info.getHeaders())
        body = req[info.getBodyOffset():]

        new_headers = []
        for h in headers:
            name = h.split(":", 1)[0]
            lname = name.lower()
            # strip identity headers - we re-add per-user ones below
            if lname == "cookie":
                continue
            if lname in user.headers:
                continue
            if lname == "content-length":
                continue
            if lname in ("accept-encoding",):
                # avoid compressed responses complicating diffing
                continue
            new_headers.append(h)

        # per-user headers (Authorization: Bearer .., X-API-Key, ...)
        for k, v in user.headers.items():
            if v:
                new_headers.append("%s: %s" % (k, v))

        # cookies
        if user.cookies:
            ck = "; ".join("%s=%s" % (k, v) for k, v in user.cookies.items() if v)
            if ck:
                new_headers.append("Cookie: " + ck)

        # CSRF refresh
        csrf_meta = None
        if csrf_target:
            nh = []
            for h in new_headers:
                if csrf_target["type"] == "header" and \
                        h.split(":", 1)[0].lower() == csrf_target["name"].lower():
                    if csrf_value:
                        h = "%s: %s" % (csrf_target["name"], csrf_value)
                    nh.append(h)
                else:
                    nh.append(h)
            new_headers = nh
            if csrf_target["type"] == "param" and csrf_value:
                body = re.sub(
                    re.escape(csrf_target.get("orig", "")), csrf_value, body)

        # content-length recalc
        if body:
            new_headers.append("Content-Length: %d" % len(bytearray(body, "latin-1")))

        req_line = new_headers[0]
        rest = new_headers[1:]
        out = req_line + "\r\n" + "\r\n".join(rest) + "\r\n\r\n" + (body or "")
        return out

    @staticmethod
    def find_csrf_target(endpoint):
        """Locate CSRF-ish material in the captured request: header or body param."""
        req = endpoint.request
        head, _, body = req.partition("\r\n\r\n")
        for line in head.split("\r\n")[1:]:
            name = line.split(":", 1)[0]
            if CSRF_NAME_RE.search(name):
                return {"type": "header", "name": name,
                        "orig": line.split(":", 1)[1].strip()}
        # body param
        m = re.search(r"([A-Za-z0-9_\-\[\]]*)=([^&\n]*)", body or "")
        if m and CSRF_NAME_RE.search(m.group(1)):
            return {"type": "param", "name": m.group(1), "orig": m.group(2)}
        return None


# ---------------------------------------------------------------------------
# Matrix table model
# ---------------------------------------------------------------------------

class MatrixTableModel(DefaultTableModel):
    # class-level defaults: the Java superclass constructor calls
    # getRowCount() before our __init__ body runs, so these MUST exist
    # on the class, not only on the instance.
    columns = ["ID", "Endpoint"]
    rows = []          # list of Endpoint
    results = {}       # (endpoint_id, user_name) -> Result

    def __init__(self):
        self.rows = []
        self.results = {}
        self.columns = ["ID", "Endpoint", "Score"]

    def set_users(self, users):
        # keep any object-swap columns (a->b) that were added at runtime
        swaps = [c for c in self.columns if "->" in c]
        self.columns = ["ID", "Endpoint", "Score"] + [u.name for u in users] + swaps
        self.fireTableStructureChanged()

    def ensure_column(self, name):
        if name not in self.columns:
            self.columns.append(name)
            self.fireTableStructureChanged()

    def set_data(self, endpoints):
        self.rows = list(endpoints)
        self.fireTableDataChanged()

    def put_result(self, res):
        self.results[(res.endpoint.id, res.user.name)] = res
        self.fireTableDataChanged()

    def getRowCount(self):
        return len(self.rows)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, i):
        return self.columns[i]

    def isCellEditable(self, r, c):
        return False

    def getValueAt(self, r, c):
        if c == 0:
            return str(self.rows[r].id)
        if c == 1:
            return self.rows[r].label()
        if c == 2:
            return str(endpoint_risk_score(self.rows[r]))
        # user column -> verdict cell
        col = self.columns[c]
        ep = self.rows[r]
        res = self.results.get((ep.id, col))
        if res is None:
            return ""
        base = self.results.get((ep.id, "(baseline)"))
        if base is not None and col != "(baseline)":
            # AutoRepeater-style length diff vs original identity response;
            # delta 0 + same status is a strong indicator of real access
            return "%d / %dB d%+d" % (res.status, res.length,
                                      res.length - base.length)
        return "%d / %dB" % (res.status, res.length)

    def column_class(self, c):
        return java_string_class()


def java_string_class():
    from java.lang import String
    return String


# ---------------------------------------------------------------------------
# Main tab
# ---------------------------------------------------------------------------

class MatrixTab(ITab, IMessageEditorController):
    def __init__(self, ext):
        self.ext = ext
        self.callbacks = ext.callbacks
        self._build_ui()

    # ----- ITab -----
    def getTabCaption(self):
        return "Authorba"

    def getUiComponent(self):
        return self.panel

    # ----- IMessageEditorController (for request/response viewers) -----
    def getHttpService(self):
        return self._cur_service

    def getRequest(self):
        return self._cur_request

    def getResponse(self):
        return self._cur_response

    # ----- UI construction -----
    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        # three-way draggable layout: users | endpoints | run controls,
        # built from two nested horizontal split panes
        self.cfg_split_ue = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.cfg_split_ue.setResizeWeight(0.5)
        self.cfg_split_ue.setOneTouchExpandable(True)
        self.cfg_split_all = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.cfg_split_all.setResizeWeight(0.66)
        self.cfg_split_all.setOneTouchExpandable(True)
        top = JPanel(BorderLayout())
        # header strip: "Configuration" left corner, author right corner
        header = JPanel()
        header.setLayout(BoxLayout(header, BoxLayout.X_AXIS))
        left_lbl = JLabel("Configuration")
        left_lbl.setFont(Font("Dialog", Font.BOLD, 12))
        right_lbl = JLabel("by Mr_Vill4in")
        right_lbl.setFont(Font("Dialog", Font.ITALIC, 11))
        header.add(left_lbl)
        header.add(Box.createHorizontalGlue())
        header.add(right_lbl)
        top.add(header, BorderLayout.NORTH)
        top.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8))

        # --- roles / users panel
        users_panel = JPanel(BorderLayout())
        users_panel.setBorder(BorderFactory.createTitledBorder("Roles & Users"))
        users_panel.setPreferredSize(Dimension(260, 240))
        self.role_model = DefaultListModel()
        self.role_list = JList(self.role_model)
        self.role_list.setVisibleRowCount(6)
        users_panel.add(JScrollPane(self.role_list), BorderLayout.CENTER)

        ub = JPanel(FlowLayout(FlowLayout.LEFT))
        self.btn_add_user = JButton("Add User", actionPerformed=self.on_add_user)
        self.btn_edit_user = JButton("Edit User", actionPerformed=self.on_edit_user)
        self.btn_del_user = JButton("Delete User", actionPerformed=self.on_del_user)
        for b in (self.btn_add_user, self.btn_edit_user, self.btn_del_user):
            ub.add(b)
        users_panel.add(ub, BorderLayout.SOUTH)
        self.cfg_split_ue.setLeftComponent(users_panel)

        # --- endpoints panel
        ep_panel = JPanel(BorderLayout())
        ep_panel.setBorder(BorderFactory.createTitledBorder(
            "Endpoints (auto-captured from Proxy; static assets skipped)"))
        ep_panel.setPreferredSize(Dimension(340, 240))
        self.ep_model = DefaultListModel()
        self.ep_list = JList(self.ep_model)
        ep_panel.add(JScrollPane(self.ep_list), BorderLayout.CENTER)
        eb = JPanel(FlowLayout(FlowLayout.LEFT))
        self.btn_del_ep = JButton("Remove", actionPerformed=self.on_del_endpoint)
        self.btn_clear_ep = JButton("Clear All", actionPerformed=self.on_clear_endpoints)
        self.btn_perms = JButton("Role Permissions", actionPerformed=self.on_permissions)
        self.btn_allow_write = JButton("Allow Write Replay", actionPerformed=self.on_allow_write)
        eb.add(self.btn_del_ep); eb.add(self.btn_clear_ep); eb.add(self.btn_perms)
        eb.add(self.btn_allow_write)
        ep_panel.add(eb, BorderLayout.SOUTH)
        self.cfg_split_ue.setRightComponent(ep_panel)
        self.cfg_split_all.setLeftComponent(self.cfg_split_ue)

        # --- run controls
        run_panel = JPanel(BorderLayout())
        run_panel.setBorder(BorderFactory.createTitledBorder("Test Run"))
        run_panel.setPreferredSize(Dimension(430, 240))
        self.btn_run = JButton("Run All Tests", actionPerformed=self.on_run)
        self.btn_stop = JButton("Stop", actionPerformed=self.on_stop)
        self.chk_live_capture = JCheckBox("Live capture from Proxy: ON", True)
        self.chk_live_capture.addActionListener(self._on_toggle_capture)
        self.btn_capture_history = JButton(
            "Pull Endpoints from History (scope filter applies)", actionPerformed=self.on_capture_history)
        self.lbl_capture_status = JLabel(" ")
        self.chk_scope = JCheckBox("Only capture in-scope (Target scope)", False)
        self.chk_skip_static = JCheckBox("Skip static assets", True)
        self.chk_mask = JCheckBox("Mask dynamic values", True)
        self.chk_safe_write = JCheckBox("Safe mode: GET/HEAD only", True)
        self.chk_autotest = JCheckBox("Auto-test new endpoints (Autorize-style)", False)
        self.chk_repeater = JCheckBox("Capture Repeater traffic", False)
        self.chk_authonly = JCheckBox("Only capture requests carrying auth", False)
        self.chk_dryrun = JCheckBox("Dry run (send nothing, list candidates)", False)
        self.txt_delay = JTextField("250", 8)
        self.btn_check_sessions = JButton("Check Sessions", actionPerformed=self.on_check_sessions)
        self.btn_export_csv = JButton("Export CSV", actionPerformed=lambda e: self.ext.export_csv())
        self.txt_deny_re = JTextField(
            r"(?i)(forbidden|unauthorized|access denied|not authorized|insufficient)", 30)
        self.progress = JProgressBar()
        self.progress.setStringPainted(True)
        # two-column grid keeps the panel compact and lets it scale
        rp = JPanel(GridLayout(0, 2, 4, 2))
        rp.add(self.btn_run)
        rp.add(self.btn_stop)
        rp.add(self.btn_capture_history)
        rp.add(self.btn_check_sessions)
        rp.add(self.progress)
        rp.add(self.lbl_capture_status)
        rp.add(self.chk_live_capture)
        rp.add(self.chk_scope)
        rp.add(self.chk_skip_static)
        rp.add(self.chk_authonly)
        rp.add(self.chk_repeater)
        rp.add(self.chk_mask)
        rp.add(self.chk_safe_write)
        rp.add(self.chk_autotest)
        rp.add(self.chk_dryrun)
        rp.add(JLabel("Delay (ms):"))
        rp.add(self.txt_delay)
        rp.add(JLabel("Denial markers (regex):"))
        rp.add(self.txt_deny_re)
        run_panel.add(rp, BorderLayout.CENTER)
        rp2 = JPanel(GridLayout(0, 1, 4, 2))
        self.btn_jwt = JButton("Inspect JWT", actionPerformed=self.on_jwt)
        self.btn_export_json = JButton("Export JSON", actionPerformed=lambda e: self.ext.export_json())
        self.btn_export_html = JButton("Export HTML", actionPerformed=lambda e: self.ext.export_html())
        rp2.add(self.btn_jwt)
        rp2.add(self.btn_export_json)
        rp2.add(self.btn_export_html)
        rp2.add(self.btn_export_csv)
        run_panel.add(rp2, BorderLayout.EAST)
        self.cfg_split_all.setRightComponent(run_panel)
        top.add(self.cfg_split_all, BorderLayout.CENTER)

        # --- matrix + viewers split
        self.table_model = MatrixTableModel()
        self._renderer = VerdictRenderer(self.table_model)
        self.table = JTable(self.table_model)
        self.table.setDefaultRenderer(java_string_class(), self._renderer)
        self.table.setRowSelectionAllowed(True)
        self.table.setColumnSelectionAllowed(True)
        self.table.setCellSelectionEnabled(True)
        self.table.addMouseListener(MatrixMouseAdapter(self))

        self.req_viewer = self.callbacks.createMessageEditor(self, False)
        self.resp_viewer = self.callbacks.createMessageEditor(self, False)

        sp = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                        JScrollPane(self.table),
                        JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                   self.req_viewer.getComponent(),
                                   self.resp_viewer.getComponent()))
        sp.setResizeWeight(0.55)
        # draggable divider between config strip and matrix: every region
        # scales when the Burp window resizes or the divider is moved
        self.main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, sp)
        self.main_split.setResizeWeight(0.0)
        self.main_split.setOneTouchExpandable(True)
        self.panel.add(self.main_split, BorderLayout.CENTER)

        # divider positions only take effect once the UI is realized
        def _set_dividers():
            try:
                self.cfg_split_ue.setDividerLocation(0.5)
                self.cfg_split_all.setDividerLocation(0.62)
                self.main_split.setDividerLocation(0.34)
            except Exception:
                pass
        SwingUtilities.invokeLater(_set_dividers)

        self._cur_service = None
        self._cur_request = None
        self._cur_response = None

    def refresh_all(self):
        self.role_model.clear()
        for u in self.ext.users:
            self.role_model.addElement("%s  [%s]%s" % (
                u.name, u.role, "" if u.enabled else " (disabled)"))
        self.ep_model.clear()
        for ep in self.ext.endpoints:
            self.ep_model.addElement("#%d %s" % (ep.id, ep.label()))
        self.table_model.set_users(self.ext.users)
        self.table_model.set_data(self.ext.endpoints)

    # ----- actions -----
    def _parent_window(self):
        """The real Burp window owning this tab - dialogs parented to a bare
        JFrame() float behind Burp and lose modality."""
        return SwingUtilities.getWindowAncestor(self.panel)

    def _selected_user(self):
        """User object for the current Users-list selection, or None."""
        idx = self.role_list.getSelectedIndex()
        if idx < 0 or idx >= len(self.ext.users):
            JOptionPane.showMessageDialog(
                self.panel, "Select a user in the Roles & Users list first.")
            return None
        return self.ext.users[idx]

    def on_add_user(self, e):
        dlg = UserDialog(self._parent_window(), "Add User", self.ext, None)
        dlg.setVisible(True)
        self.refresh_all()

    def on_edit_user(self, e):
        user = self._selected_user()
        if user is None:
            return
        dlg = UserDialog(self._parent_window(), "Edit User: %s" % user.name, self.ext, user)
        dlg.setVisible(True)
        self.refresh_all()

    def on_del_user(self, e):
        user = self._selected_user()
        if user is None:
            return
        if JOptionPane.showConfirmDialog(
                self.panel, "Delete user '%s' (role %s)?" % (user.name, user.role),
                "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            self.ext.users = [u for u in self.ext.users if u is not user]
            self.ext.save_config()
            self.refresh_all()

    def on_del_endpoint(self, e):
        idx = self.ep_list.getSelectedIndex()
        if idx >= 0:
            del self.ext.endpoints[idx]
            self.refresh_all()

    def on_clear_endpoints(self, e):
        if JOptionPane.showConfirmDialog(self.panel, "Remove all endpoints?",
                                         "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            self.ext.endpoints = []
            self.refresh_all()

    def on_allow_write(self, e):
        """Toggle write-replay opt-in for the selected endpoint(s)."""
        idx = self.ep_list.getSelectedIndex()
        if idx < 0 or idx >= len(self.ext.endpoints):
            JOptionPane.showMessageDialog(self.panel,
                                         "Select an endpoint in the Endpoints list first.")
            return
        ep = self.ext.endpoints[idx]
        ep.write_allowed = not ep.write_allowed
        self.refresh_all()

    def _on_toggle_capture(self, e):
        on = self.chk_live_capture.isSelected()
        self.chk_live_capture.setText(
            "Live capture from Proxy: %s" % ("ON" if on else "OFF"))
        self.lbl_capture_status.setText(
            "Live capture %s - %s" % (
                "enabled" if on else "disabled",
                "new proxied traffic %s be captured" % ("will" if on else "will NOT")))

    def on_check_sessions(self, e):
        thread.start_new_thread(self.ext.check_sessions, ())

    def on_capture_history(self, e):
        """Manually pull endpoints from existing Proxy history."""
        n = self.ext.capture_proxy_history()
        self.lbl_capture_status.setText(
            "Imported %d new endpoint(s) from Proxy history" % n)
        self.refresh_all()

    def on_permissions(self, e):
        dlg = PermissionsDialog(self._parent_window(), self.ext)
        dlg.setVisible(True)
        self.refresh_all()

    def on_run(self, e):
        if not self.ext.endpoints:
            JOptionPane.showMessageDialog(self.panel, "No endpoints captured yet.")
            return
        if not self.ext.users:
            JOptionPane.showMessageDialog(self.panel, "Add users first.")
            return
        self.ext.run_tests()

    def on_stop(self, e):
        self.ext.stop_flag = True

    def on_jwt(self, e):
        token = JOptionPane.showInputDialog(self.panel, "Paste JWT / Bearer token:")
        if not token:
            return
        token = BEARER_RE.sub(r"\1", token)
        JOptionPane.showMessageDialog(self.panel, jwt_summary(token))

    # ----- cell inspection -----
    def show_cell(self, row, col):
        if col < 3 or row < 0 or row >= len(self.table_model.rows):
            return
        ep = self.table_model.rows[row]
        user_name = self.table_model.columns[col]
        res = self.table_model.results.get((ep.id, user_name))
        if res is None:
            return
        h = self.callbacks.getHelpers()
        self._cur_service = h.buildHttpService(ep.host, ep.port, ep.ssl)
        # guard: message data must never be None or the editors blank out
        req_bytes = h.stringToBytes(res.request or "")
        resp_bytes = h.stringToBytes(res.response or "")
        self._cur_request = req_bytes
        self._cur_response = resp_bytes
        try:
            self.req_viewer.setMessage(req_bytes, True)
        except Exception:
            pass
        try:
            self.resp_viewer.setMessage(resp_bytes, False)
        except Exception:
            pass
        self.ext.log(
            "Inspecting endpoint #%d vs %s: %s (HTTP %d, resp %dB)" % (
                ep.id, user_name, res.verdict, res.status,
                len(res.response or "")))

    def cell_at(self, e):
        """Return (ep, res, row, col) for a mouse event, or (None,)*4."""
        row = self.table.rowAtPoint(e.getPoint())
        col = self.table.columnAtPoint(e.getPoint())
        if col < 3 or row < 0 or row >= len(self.table_model.rows):
            return None, None, row, col
        ep = self.table_model.rows[row]
        user_name = self.table_model.columns[col]
        res = self.table_model.results.get((ep.id, user_name))
        return ep, res, row, col

    def send_cell_to_repeater(self, ep, res):
        try:
            self.callbacks.sendToRepeater(
                ep.host, ep.port, ep.ssl,
                self.callbacks.getHelpers().stringToBytes(res.request or ""),
                "Authorba: %s" % ep.label())
        except Exception:
            traceback.print_exc()

    def retest_endpoint(self, ep):
        users = [u for u in self.ext.users if u.enabled]
        if not users:
            self.ext.log("Re-test skipped: no enabled users")
            return
        thread.start_new_thread(self.ext._test_endpoint, (ep, users))


class MatrixMouseAdapter(MouseAdapter):
    def __init__(self, tab):
        self.tab = tab

    def mouseReleased(self, e):
        self._handle(e)

    def mousePressed(self, e):
        self._handle(e)

    def _handle(self, e):
        if SwingUtilities.isRightMouseButton(e):
            self._popup(e)
            return
        row = self.tab.table.rowAtPoint(e.getPoint())
        col = self.tab.table.columnAtPoint(e.getPoint())
        self.tab.show_cell(row, col)

    def _popup(self, e):
        from javax.swing import JPopupMenu
        ep, res, row, col = self.tab.cell_at(e)
        if ep is None:
            return
        self.tab.table.setRowSelectionInterval(row, row)
        self.tab.table.setColumnSelectionInterval(col, col)
        menu = JPopupMenu("Authorba")

        if res is not None:
            item = JMenuItem("View request / response")
            t, r, c = self.tab, row, col
            item.addActionListener(lambda ev: t.show_cell(r, c))
            menu.add(item)

            if res.request:
                item2 = JMenuItem("Send to Repeater")
                t2, e2, r2 = self.tab, ep, res
                item2.addActionListener(lambda ev: t2.send_cell_to_repeater(e2, r2))
                menu.add(item2)
        else:
            info = JMenuItem("No result for this cell - run tests first", 0)
            info.setEnabled(False)
            menu.add(info)

        menu.addSeparator()
        item3 = JMenuItem("Re-test endpoint %s" % ep.label())
        t3, e3 = self.tab, ep
        item3.addActionListener(lambda ev: t3.retest_endpoint(e3))
        menu.add(item3)

        menu.show(e.getComponent(), e.getX(), e.getY())


from javax.swing.table import DefaultTableCellRenderer


class VerdictRenderer(DefaultTableCellRenderer):
    def __init__(self, model):
        DefaultTableCellRenderer.__init__(self)
        self.model = model

    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, focus, row, col)
        c.setOpaque(True)
        if col == 2:
            # risk score cell - subtle heat coloring
            try:
                sc = int(value)
            except Exception:
                sc = 0
            if sc >= 70:
                c.setBackground(Color(0xFF, 0xE0, 0xB2))
            elif sc >= 40:
                c.setBackground(Color(0xFF, 0xF3, 0xE0))
            else:
                c.setBackground(Color.WHITE)
            return c
        if col >= 3 and row < self.model.getRowCount():
            ep = self.model.rows[row]
            user_name = self.model.columns[col]
            res = self.model.results.get((ep.id, user_name))
            if res is not None and not sel:
                c.setBackground(VERDICT_COLORS.get(res.verdict, Color.WHITE))
                c.setForeground(Color.WHITE if res.verdict in (
                    V_FINDING, V_BLOCKED, V_ERROR) else Color.BLACK)
                tip = "%s | %s | status=%d len=%d sim=%.2f err=%s" % (
                    res.verdict, res.user.name, res.status, res.length,
                    res.similarity, res.error)
                base = self.model.results.get((ep.id, "(baseline)"))
                if base is not None:
                    d = res.length - base.length
                    tip += " | len-diff %+d" % d
                    if res.status == base.status and d == 0:
                        tip += " (same status + len-diff 0 => likely real access)"
                c.setToolTipText(tip)
        elif not sel:
            c.setBackground(Color.WHITE)
        return c


# ---------------------------------------------------------------------------
# User editor dialog
# ---------------------------------------------------------------------------

class UserDialog(JDialog):
    def __init__(self, parent, title, ext, user):
        JDialog.__init__(self, parent, title, True)
        self.ext = ext
        self.user = user
        self.setSize(640, 560)
        self.setLocationRelativeTo(parent)
        self.setLayout(BorderLayout())
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        roles = list(ext.get_roles())
        if user and user.role not in roles:
            roles.append(user.role)
        self.cmb_role = JComboBox(roles)
        self.cmb_role.setEditable(True)   # pick an existing role or type a new one
        if user:
            self.cmb_role.setSelectedItem(user.role)
        self.txt_name = JTextField(user.name if user else "", 20)
        self.chk_enabled = JCheckBox("Enabled", user.enabled if user else True)

        panel.add(self._row("User name:", self.txt_name))
        panel.add(self._row("Role:", self.cmb_role))
        panel.add(self._row("", self.chk_enabled))

        self.txt_cookies = JTextArea(
            "\n".join("%s=%s" % (k, v) for k, v in (user.cookies if user else {}).items()), 4, 40)
        self.txt_headers = JTextArea(
            "\n".join("%s: %s" % (k, v) for k, v in (user.headers if user else {}).items()), 4, 40)
        panel.add(self._row("Cookies (one name=value per line, replaces Cookie header):",
                            JScrollPane(self.txt_cookies)))
        panel.add(self._row("Headers (one 'Name: value' per line, e.g. Authorization: Bearer xx):",
                            JScrollPane(self.txt_headers)))
        self.txt_objects = JTextArea(
            "\n".join("%s=%s" % (k, v) for k, v in (user.objects if user else {}).items()), 3, 40)
        panel.add(self._row("Owned objects (resource=id per line, e.g. orders=1001 users=2; "
                            "used for object-swap BOLA testing):",
                            JScrollPane(self.txt_objects)))
        self.txt_canary = JTextField(user.canary if user else "", 40)
        panel.add(self._row("Canary marker (string unique to this user, e.g. their email; "
                            "appearing in ANOTHER user's response = leak):",
                            self.txt_canary))

        self.txt_refresh_req = JTextArea(user.refresh_request if user else "", 5, 40)
        panel.add(self._row("Session refresh request (raw HTTP, optional; sent when refresh regexes set or on demand):",
                            JScrollPane(self.txt_refresh_req)))
        self.txt_refresh_cookie_re = JTextField(user.refresh_cookies_re if user else "", 40)
        panel.add(self._row("Regex to extract new Cookie from refresh response (group 1):",
                            self.txt_refresh_cookie_re))
        self.txt_refresh_header_re = JTextField(user.refresh_headers_re if user else "", 40)
        panel.add(self._row("Regex to extract new token from refresh response (group 1):",
                            self.txt_refresh_header_re))
        self.txt_refresh_header_name = JTextField(user.refresh_header_name if user else "Authorization", 20)
        panel.add(self._row("Header name for extracted token:", self.txt_refresh_header_name))

        self.add(JScrollPane(panel), BorderLayout.CENTER)
        btns = JPanel()
        ok = JButton("Save", actionPerformed=self.on_save)
        cancel = JButton("Cancel", actionPerformed=lambda e: self.dispose())
        refresh_now = JButton("Run Refresh Now", actionPerformed=self.on_refresh_now)
        btns.add(refresh_now); btns.add(ok); btns.add(cancel)
        self.add(btns, BorderLayout.SOUTH)

    def _row(self, label, comp):
        p = JPanel(BorderLayout())
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0))
        p.add(JLabel(label), BorderLayout.NORTH)
        p.add(comp, BorderLayout.CENTER)
        return p

    def _collect(self):
        role = (self.cmb_role.getSelectedItem() or "").strip() or "unknown"
        name = self.txt_name.getText().strip()
        if not name:
            JOptionPane.showMessageDialog(self, "User name required.")
            return None
        u = self.user or User(name, role)
        u.name = name
        u.role = role
        u.enabled = self.chk_enabled.isSelected()
        u.cookies = {}
        for line in self.txt_cookies.getText().splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                u.cookies[k.strip()] = v.strip()
        u.headers = {}
        for line in self.txt_headers.getText().splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                u.headers[k.strip()] = v.strip()
        u.objects = {}
        for line in self.txt_objects.getText().splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                u.objects[k.strip()] = v.strip()
        u.canary = self.txt_canary.getText().strip()
        u.refresh_request = self.txt_refresh_req.getText() or None
        u.refresh_cookies_re = self.txt_refresh_cookie_re.getText()
        u.refresh_headers_re = self.txt_refresh_header_re.getText()
        u.refresh_header_name = self.txt_refresh_header_name.getText().strip() or "Authorization"
        return u

    def on_save(self, e):
        u = self._collect()
        if u is None:
            return
        if self.user is None:
            self.ext.users.append(u)
        self.ext.save_config()
        self.dispose()

    def on_refresh_now(self, e):
        u = self._collect()
        if u is None or not u.refresh_request:
            JOptionPane.showMessageDialog(self, "Provide a refresh request first.")
            return
        ok, msg = self.ext.refresh_session(u)
        JOptionPane.showMessageDialog(self, msg)


# ---------------------------------------------------------------------------
# Permissions matrix dialog (endpoint x role allow checkboxes)
# ---------------------------------------------------------------------------

class PermissionsTableModel(DefaultTableModel):
    # class-level defaults for the same Jython constructor-dispatch reason
    columns = ["ID", "Endpoint", "Category"]
    roles = []
    endpoints = []

    def __init__(self, ext, endpoints):
        self.ext = ext
        self.endpoints = endpoints
        self.roles = ext.get_roles()
        self.columns = ["ID", "Endpoint", "Category"] + list(self.roles)
        if not self.roles:
            self.columns = ["ID", "Endpoint", "Category"]

    def getRowCount(self):
        return len(self.endpoints)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, i):
        return self.columns[i]

    def getColumnClass(self, c):
        from java.lang import Boolean
        return Boolean if c >= 3 else java_string_class()

    def isCellEditable(self, r, c):
        return c >= 3

    def getValueAt(self, r, c):
        from java.lang import Boolean as JBoolean
        if c == 0:
            return str(self.endpoints[r].id)
        if c == 1:
            return self.endpoints[r].label()
        if c == 2:
            return self.endpoints[r].category()
        role = self.columns[c]
        return JBoolean(self.ext.is_allowed(self.endpoints[r], role))

    def setValueAt(self, val, r, c):
        role = self.columns[c]
        ep = self.endpoints[r]
        # val can be java.lang.Boolean, python bool, or String depending on editor
        on = val is True or str(val).lower() == "true"
        self.ext.set_allowed(ep, role, on)
        self.fireTableCellUpdated(r, c)


class PermissionsDialog(JDialog):
    def __init__(self, parent, ext):
        JDialog.__init__(self, parent, "Role Permissions (allowed endpoints per role)", True)
        self.ext = ext
        self.setSize(900, 500)
        self.setLocationRelativeTo(parent)
        self.setLayout(BorderLayout())
        if not ext.get_roles():
            self.add(JLabel("No roles defined yet - add users first."), BorderLayout.CENTER)
            return
        self.model = PermissionsTableModel(ext, ext.endpoints)
        self.table = JTable(self.model)
        self.add(JScrollPane(self.table), BorderLayout.CENTER)
        b = JPanel()
        b.add(JButton("Close", actionPerformed=lambda e: self.dispose()))
        self.add(b, BorderLayout.SOUTH)


# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IProxyListener, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Authorba (BOLA/BFLA/BOPLA)")
        self.stdout = callbacks.getStdout()
        try:
            from java.io import PrintWriter
            from java.io import PrintStream
            import sys
            sys.stdout = self._jstream(self.stdout)
        except Exception:
            pass

        self.endpoints = []
        self.users = []
        self.permissions = {}   # endpoint_key -> {role: bool}
        self.builder = RequestBuilder(callbacks)
        self.stop_flag = False
        self.baselines = {}     # endpoint_id -> Result with original identity

        self.load_config()

        self.tab = MatrixTab(self)
        callbacks.addSuiteTab(self.tab)
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)

        # context menu to add request from anywhere
        self.menu_btn = self._make_menu_button()
        callbacks.registerContextMenuFactory(self.menu_btn)

        self.tab.refresh_all()
        log("Loaded. Capture requests via Proxy (or right-click -> Add to Authorba), "
            "configure users, set role permissions, then Run All Tests.")

    def _jstream(self, ostream):
        from java.io import PrintWriter
        class S:
            def write(self, s):
                ostream.write(s.encode("utf-8") if isinstance(s, unicode) else str(s))
                ostream.flush()
            def flush(self):
                ostream.flush()
        return S()

    # ---------------- persistence ----------------
    CONFIG_FILE = "authorba_config.json"
    LEGACY_CONFIG_FILES = ["authorbo_config.json", "auth_matrix_config.json"]  # older names

    def _config_path(self, fname=None):
        try:
            from java.lang import System
            home = System.getProperty("user.home")
        except Exception:
            home = "."
        import os
        return os.path.join(unicode(home), fname or self.CONFIG_FILE)

    def save_config(self):
        try:
            cfg = {
                "users": [u.to_dict() for u in self.users],
                "permissions": self.permissions,
            }
            with open(self._config_path(), "w") as f:
                json.dump(cfg, f, indent=2)
            log("Config saved (%d users)" % len(self.users))
        except Exception as e:
            log("save_config failed: %s" % e)

    def load_config(self):
        import os
        p = self._config_path()
        if not os.path.exists(p):
            # fall back to older config names so nothing is lost across renames
            for legacy_name in self.LEGACY_CONFIG_FILES:
                legacy = self._config_path(legacy_name)
                if os.path.exists(legacy):
                    p = legacy
                    break
            else:
                return
        try:
            with open(p) as f:
                cfg = json.load(f)
            self.users = [User.from_dict(d) for d in cfg.get("users", [])]
            self.permissions = cfg.get("permissions", {})
            log("Loaded %d users from config" % len(self.users))
        except Exception as e:
            log("load_config failed: %s" % e)

    # ---------------- helpers ----------------
    def get_roles(self):
        seen, out = [], []
        for u in self.users:
            if u.role not in seen:
                seen.append(u.role)
                out.append(u.role)
        return out

    def is_allowed(self, ep, role):
        return bool(self.permissions.get(ep.endpoint_key, {}).get(role, False))

    def set_allowed(self, ep, role, val):
        d = self.permissions.setdefault(ep.endpoint_key, {})
        d[role] = bool(val)
        self.save_config()

    def log(self, msg):
        log(msg)

    def add_endpoint_from_message(self, message_info):
        """Add an IInterceptedProxyMessage / IHttpRequestResponse endpoint."""
        try:
            req_info = self.helpers.analyzeRequest(message_info)
            headers = list(req_info.getHeaders())
            if not headers:
                return False
            first = headers[0]
            parts = first.split(" ")
            if len(parts) < 2:
                return False
            method, path = parts[0], parts[1]
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                return False
            if self.tab.chk_skip_static.isSelected() and is_static_asset(path):
                return False
            # optional filter: skip requests with no auth material at all
            if self.tab.chk_authonly.isSelected():
                hdr_names = [h.split(":", 1)[0].strip().lower()
                             for h in headers[1:] if ":" in h]
                if not any(n in ("cookie", "authorization", "x-api-key",
                                 "x-auth-token", "x-access-token",
                                 "x-session-token", "api-key", "apikey")
                           for n in hdr_names):
                    return False
            svc = message_info.getHttpService()
            req_bytes = self.helpers.bytesToString(message_info.getRequest())
            ep = Endpoint(method, path, svc.getHost(), svc.getPort(),
                          svc.getProtocol() == "https", req_bytes)
            key = (ep.method, ep.endpoint_key, svc.getHost())
            for existing in self.endpoints:
                if (existing.method, existing.endpoint_key, existing.host) == key:
                    return False  # dedupe on normalized (templated) path
            self.endpoints.append(ep)
            if len(self.endpoints) % 10 == 0:
                SwingUtilities.invokeLater(self._refresh_tab())
            # Autorize-style passive testing: test new endpoints immediately
            if self.tab.chk_autotest.isSelected() and self.users:
                thread.start_new_thread(self._autotest_endpoint, (ep,))
            return True
        except Exception:
            traceback.print_exc()
            return False

    def _refresh_tab(self):
        self.tab.refresh_all()

    # ---------------- IProxyListener ----------------
    def check_sessions(self):
        """Verify each configured user's session is still live by sending a
        harmless GET (to the first captured endpoint's host, or the refresh
        request's host) with that user's auth material."""
        lines = []
        host = port = ssl = None
        if self.endpoints:
            host, port, ssl = self.endpoints[0].host, self.endpoints[0].port, self.endpoints[0].ssl
        for u in self.users:
            if not u.enabled or not (u.cookies or u.headers):
                continue
            try:
                if host is None and u.refresh_request:
                    for line in u.refresh_request.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host, port, ssl = line.split(":", 1)[1].strip(), 80, False
                if host is None:
                    lines.append("%s: no target host (capture an endpoint first)" % u.name)
                    continue
                probe = User(u.name, u.role)
                probe.cookies = u.cookies
                probe.headers = u.headers
                fake_ep = Endpoint("GET", "/", host, port, ssl, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host)
                res = self._send(fake_ep, probe)
                alive = 200 <= res.status < 500 and res.status not in (401, 403)
                if 200 <= res.status < 400:
                    state = "ALIVE (HTTP %d)" % res.status
                elif res.status in (401, 403):
                    state = "DEAD - session rejected (HTTP %d) - refresh it" % res.status
                else:
                    state = "unclear (HTTP %d)" % res.status
                lines.append("%s [%s]: %s" % (u.name, u.role, state))
            except Exception as ex:
                lines.append("%s: check failed (%s)" % (u.name, ex))
        msg = "\n".join(lines) or "No users with credentials configured."
        log("Session check:\n" + msg)
        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
            None, msg, "Session Check", JOptionPane.INFORMATION_MESSAGE))

    def _autotest_endpoint(self, ep):
        """Passive single-endpoint test (background thread)."""
        try:
            users = [u for u in self.users if u.enabled]
            if not users:
                return
            self._test_endpoint(ep, users)
            SwingUtilities.invokeLater(self._refresh_tab)
            log("Auto-tested %s (findings so far: %d)" % (
                ep.label(), self._count_findings()))
            if self._count_findings():
                self.callbacks.issueAlert(
                    "Authorba: %d potential broken access control findings!" %
                    self._count_findings())
        except Exception:
            traceback.print_exc()

    def capture_proxy_history(self):
        """Pull all (optionally in-scope) items from Burp's Proxy history as
        endpoints. Returns the number newly added."""
        added = 0
        skipped_out_of_scope = [0]
        try:
            history = self.callbacks.getProxyHistory()
            in_scope_only = self.tab.chk_scope.isSelected()

            def check_item(item):
                try:
                    if in_scope_only:
                        url = item.getUrl()
                        if url and not self.callbacks.isInScope(url.toString()):
                            skipped_out_of_scope[0] += 1
                            return False
                except Exception:
                    pass
                return self.add_endpoint_from_message(item)

            for item in history:
                try:
                    if check_item(item):
                        added += 1
                except Exception:
                    continue
            log("Proxy history pull: %d new endpoint(s), %d out-of-scope skipped"
                % (added, skipped_out_of_scope[0]))
        except Exception:
            traceback.print_exc()
        return added

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        """Capture traffic from other Burp tools (e.g. Repeater) when the
        user opted in. Only responses (completed exchanges) are captured."""
        if messageIsRequest:
            return
        if not self.tab.chk_repeater.isSelected():
            return
        try:
            if toolFlag != self.callbacks.TOOL_REPEATER:
                return
            if self.add_endpoint_from_message(message):
                SwingUtilities.invokeLater(self._refresh_tab)
        except Exception:
            pass

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            return
        if not self.tab.chk_live_capture.isSelected():
            return
        if self.tab.chk_scope.isSelected():
            try:
                mi = message.getMessageInfo()
                svc = mi.getHttpService()
                url = "http%s://%s%s" % ("s" if svc.getProtocol() == "https" else "",
                                         svc.getHost(), self.helpers.analyzeRequest(mi).getUrl().getPath())
                if not self.callbacks.isInScope(url):
                    return
            except Exception:
                pass
        self.add_endpoint_from_message(message.getMessageInfo())

    # ---------------- context menu ----------------
    def _make_menu_button(self):
        ext = self

        class Factory(IContextMenuFactory):
            def createMenuItems(self, inv):
                from java.util import ArrayList
                items = ArrayList()

                item = JMenuItem("Add to Authorba")
                class AddL(ActionListener):
                    def actionPerformed(self, e):
                        sel = inv.getSelectedMessages()
                        if sel:
                            for m in sel:
                                if ext.add_endpoint_from_message(m):
                                    log("Endpoint added from context menu")
                            SwingUtilities.invokeLater(ext._refresh_tab)
                item.addActionListener(AddL())
                items.add(item)

                item2 = JMenuItem("Create User from this Request's Auth")
                class UserL(ActionListener):
                    def actionPerformed(self, e):
                        sel = inv.getSelectedMessages()
                        if sel:
                            ext.create_user_from_message(sel[0])
                item2.addActionListener(UserL())
                items.add(item2)

                item3 = JMenuItem("Set as Session-Refresh Request for User...")
                class RefL(ActionListener):
                    def actionPerformed(self, e):
                        sel = inv.getSelectedMessages()
                        if sel:
                            ext.set_refresh_request_from_message(sel[0])
                item3.addActionListener(RefL())
                items.add(item3)
                return items
        return Factory()

    def create_user_from_message(self, message_info):
        """Extract Cookie / Authorization material from a request and register
        it as a new user."""
        try:
            info = self.helpers.analyzeRequest(message_info)
            headers = list(info.getHeaders())
            name = JOptionPane.showInputDialog("New user name:")
            if not name:
                return
            role = JOptionPane.showInputDialog("Role for %s:" % name) or "unknown"
            u = User(name, role)
            for h in headers:
                if ":" not in h:
                    continue
                k, _, v = h.partition(":")
                v = v.strip()
                lk = k.lower()
                if lk == "cookie":
                    for part in v.split(";"):
                        if "=" in part:
                            ck, _, cv = part.partition("=")
                            u.cookies[ck.strip()] = cv.strip()
                elif AUTH_HEADER_RE.match(k) and "csrf" not in lk:
                    u.headers[k] = v
            self.users.append(u)
            self.save_config()
            log("User %s (role %s) created from context menu" % (name, role))
            SwingUtilities.invokeLater(self._refresh_tab)
        except Exception:
            traceback.print_exc()

    def set_refresh_request_from_message(self, message_info):
        try:
            if not self.users:
                JOptionPane.showMessageDialog(None, "No users defined yet.")
                return
            names = [u.name for u in self.users]
            sel = JOptionPane.showInputDialog(
                None, "Refresh which user's session?", "Session Refresh",
                JOptionPane.QUESTION_MESSAGE, None,
                names.toArray(java_string_class()), names[0])
            if sel is None:
                return
            user = [u for u in self.users if u.name == sel][0]
            user.refresh_request = self.helpers.bytesToString(message_info.getRequest())
            self.save_config()
            ok, msg = self.refresh_session(user)
            log("Session refresh for %s: %s" % (user.name, msg))
        except Exception:
            traceback.print_exc()

    # ---------------- session refresh ----------------
    def refresh_session(self, user):
        """Send user's refresh_request, extract new cookie/token via regexes."""
        if not user.refresh_request:
            return False, "No refresh request configured."
        try:
            # build service from first line of raw request
            first = user.refresh_request.split("\r\n")[0]
            # need Host header
            host, port, ssl = "localhost", 80, False
            for line in user.refresh_request.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
            svc = self.helpers.buildHttpService(host, port, ssl)
            resp = self.callbacks.makeHttpRequest(svc, self.helpers.stringToBytes(user.refresh_request))
            analyzed = self.helpers.analyzeResponse(resp.getResponse())
            body = self.helpers.bytesToString(resp.getResponse())[analyzed.getBodyOffset():]
            headers = list(analyzed.getHeaders())
            changed = []
            if user.refresh_cookies_re:
                m = re.search(user.refresh_cookies_re, body + "\n".join(headers))
                if m:
                    val = m.group(1)
                    # replace all cookies with single session cookie
                    user.cookies = {"session": val} if "=" not in val else dict([val.split("=", 1)])
                    changed.append("cookie updated")
            if user.refresh_headers_re:
                m = re.search(user.refresh_headers_re, body)
                if m:
                    user.headers[user.refresh_header_name] = m.group(1)
                    changed.append("%s updated" % user.refresh_header_name)
            user.last_refresh = time.time()
            self.save_config()
            if changed:
                return True, "Refresh OK: " + ", ".join(changed)
            return False, "Refresh sent, but no tokens matched the regexes."
        except Exception as e:
            return False, "Refresh failed: %s" % e

    # ---------------- test engine ----------------
    def run_tests(self):
        self.stop_flag = False
        thread.start_new_thread(self._run_tests_thread, ())

    def replay_delay(self):
        """Configured min interval between replays (ms), for rate limiting."""
        try:
            return max(0, int(self.tab.txt_delay.getText().strip() or "0"))
        except Exception:
            return 250

    def _test_endpoint(self, ep, users):
        """Three-state test of a single endpoint (baseline / per-user /
        unauth) with canary + infra guards. Used by both Run All Tests and
        passive auto-test on capture."""
        # dry run: list candidates, send nothing
        if self.tab.chk_dryrun.isSelected():
            for u in users:
                r = Result(ep, u)
                r.verdict = V_SKIPPED
                r.error = "dry run - not sent"
                self.tab.table_model.put_result(r)
            return
        # write-method safety
        if not self._is_safe_replay(ep):
            for u in users:
                r = Result(ep, u)
                r.verdict = V_SKIPPED
                r.error = "write method not opted in (safe mode)"
                self.tab.table_model.put_result(r)
            return
        # baseline: original captured identity
        base = self._send(ep, None)
        self.baselines[ep.id] = base
        # keep baseline accessible to the table model for length-diff cells
        base.user = User("(baseline)", "-")
        self.tab.table_model.results[(ep.id, "(baseline)")] = base

        # unauthenticated probe (three-state model)
        unauth = self._send_unauth(ep)
        unauth_col = "(no-auth)"
        if looks_like_infra_block(unauth.status, unauth.response or ""):
            unauth.verdict = V_INFRA
        elif unauth.status in (401, 403):
            unauth.verdict = V_BLOCKED
        elif 200 <= unauth.status < 400:
            u_sim = body_similarity(
                unauth.response[unauth.response.find("\r\n\r\n") + 4:] if unauth.response else "",
                base.response[base.response.find("\r\n\r\n") + 4:] if base.response else "")
            unauth.similarity = u_sim
            unauth.verdict = V_PUBLIC if u_sim >= 0.85 else V_UNVERIFIED
        else:
            unauth.verdict = V_SKIPPED
        self.tab.table_model.ensure_column(unauth_col)
        unauth.user = User(unauth_col, "anonymous")
        self.tab.table_model.put_result(unauth)
        is_public = unauth.verdict == V_PUBLIC

        for u in users:
            if self.stop_flag:
                break
            res = self._send(ep, u, baseline=base)
            final = Result(ep, u)
            final.__dict__.update(res.__dict__)
            final.verdict = self._classify(ep, u, final, base)
            # infrastructure block is not an app-authz signal
            if looks_like_infra_block(final.status, final.response or ""):
                final.verdict = V_INFRA
            # canary leak: another user's unique marker in this
            # user's response = cross-user data exposure
            if final.verdict in (V_ALLOWED, V_UNVERIFIED, V_PUBLIC) and final.response:
                rbody = final.response[final.response.find("\r\n\r\n") + 4:]
                for other in users:
                    if other is u or not other.canary:
                        continue
                    if other.canary in rbody:
                        final.verdict = V_FINDING
                        final.error = ("canary leak: response contains %s's "
                                       "marker %r" % (other.name, other.canary))
                        break
            if is_public and final.verdict in (V_ALLOWED, V_UNVERIFIED):
                final.verdict = V_PUBLIC
            self.tab.table_model.put_result(final)

    def _run_tests_thread(self):
        try:
            endpoints = list(self.endpoints)
            users = [u for u in self.users if u.enabled]
            total = len(endpoints) * (len(users) + 1)  # +1 baseline per endpoint
            done = [0]

            def prog():
                self.tab.progress.setMaximum(total)
                self.tab.progress.setValue(done[0])

            SwingUtilities.invokeLater(prog)

            # session refresh for users that define one
            for u in users:
                if u.refresh_request and (u.refresh_cookies_re or u.refresh_headers_re):
                    ok, msg = self.refresh_session(u)
                    log("Session refresh %s: %s" % (u.name, msg))

            for ep in endpoints:
                if self.stop_flag:
                    break
                self._test_endpoint(ep, users)
                done[0] += len(users) + 1
                SwingUtilities.invokeLater(prog)
                SwingUtilities.invokeLater(self._refresh_tab)

            # ---------------- object-swap BOLA phase ----------------
            users_by_role = {}
            for u in users:
                users_by_role.setdefault(u.role, []).append(u)
            for ep in endpoints:
                if self.stop_flag:
                    break
                if not self._is_safe_replay(ep):
                    continue
                idvals = path_id_values(ep.path)
                if not idvals:
                    continue
                resource, orig_id = idvals[0]
                for role, ulist in users_by_role.items():
                    if len(ulist) < 2:
                        continue
                    for ua in ulist:
                        if ua.objects.get(resource) != orig_id:
                            # only replay endpoints captured as ua's own object
                            continue
                        for ub in ulist:
                            if ub is ua or not ub.objects.get(resource):
                                continue
                            col = "%s->%s" % (ua.name, ub.name)
                            res = self._send(ep, ua, swap=(orig_id, ub.objects[resource]))
                            shim = User(col, role)
                            res.user = shim
                            if res.verdict == V_ERROR:
                                pass
                            elif looks_like_infra_block(res.status, res.response or ""):
                                res.verdict = V_INFRA
                            elif res.status in (401, 403):
                                res.verdict = V_BLOCKED
                            elif self._denied_by_content(res) or is_empty_success(
                                    res.status,
                                    (res.response or "")[res.response.find("\r\n\r\n") + 4:] if res.response else ""):
                                res.verdict = V_BLOCKED
                            elif 200 <= res.status < 400:
                                res.verdict = V_BOLA
                            else:
                                res.verdict = V_SKIPPED
                            self.tab.table_model.ensure_column(col)
                            self.tab.table_model.put_result(res)
                            done[0] += 1
                            SwingUtilities.invokeLater(prog)

            SwingUtilities.invokeLater(self._refresh_tab)
            log("Test run complete. Findings: %d role-swap, object-swap results: %d" % (
                self._count_findings(),
                sum(1 for r in self.tab.table_model.results.values()
                    if r.verdict == V_BOLA)))
            if self._count_findings():
                self.callbacks.issueAlert("Authorba: %d potential broken access control findings!" %
                                          self._count_findings())
        except Exception:
            traceback.print_exc()

    def _count_findings(self):
        return sum(1 for r in self.tab.table_model.results.values() if r.verdict == V_FINDING)

    def _is_safe_replay(self, ep):
        """Write-safety gate. GET/HEAD/OPTIONS always safe; GraphQL queries
        are safe reads (only mutations need write opt-in)."""
        if ep.method in ("GET", "HEAD", "OPTIONS"):
            return True
        if ep.write_allowed:
            return True
        if ep.graphql:
            body = ep.request.partition("\r\n\r\n")[2]
            if re.search(r"(?s)^\s*(\{|\"query\")", body or "") or \
                    re.search(r"\bquery\b", (body or "")[:200]):
                if not re.match(r"\s*mutation", body or ""):
                    return True
        return False

    def _send_unauth(self, ep):
        """Replay with ALL auth material stripped (three-state model: the
        unauthenticated probe distinguishes real bypasses from public
        endpoints)."""
        res = Result(ep, User("(no-auth)", "anonymous"))
        try:
            head, sep, body = ep.request.partition("\r\n\r\n")
            lines = head.split("\r\n")
            kept = [lines[0]]
            for h in lines[1:]:
                name = h.split(":", 1)[0]
                if AUTH_HEADER_RE.match(name or ""):
                    continue
                if name.lower() in ("accept-encoding", "content-length"):
                    continue
                kept.append(h)
            if body:
                kept.append("Content-Length: %d" % len(bytearray(body, "latin-1")))
            req_str = "\r\n".join(kept) + "\r\n\r\n" + (body or "")
            req = self.helpers.stringToBytes(req_str)
            res.request = req_str
            svc = self.helpers.buildHttpService(ep.host, ep.port, ep.ssl)
            resp = self.callbacks.makeHttpRequest(svc, req)
            if resp.getResponse() is None:
                res.verdict = V_ERROR
                res.error = "no response"
                return res
            res.response = self.helpers.bytesToString(resp.getResponse())
            analyzed = self.helpers.analyzeResponse(
                self.helpers.stringToBytes(res.response))
            res.status = analyzed.getStatusCode()
            res.length = len(res.response) - analyzed.getBodyOffset()
        except Exception as e:
            res.verdict = V_ERROR
            res.error = str(e)
        return res

    def _denied_by_content(self, res):
        """Content-based denial detection: a 200 whose body carries denial
        markers is treated as BLOCKED, not as access."""
        if not res.response:
            return False
        deny_re = self.tab.txt_deny_re.getText().strip()
        if not deny_re:
            return False
        try:
            body = res.response[res.response.find("\r\n\r\n") + 4:]
            # only trust the marker if it appears in the first 4KB of body
            return bool(re.search(deny_re, body[:4096]))
        except Exception:
            return False

    def _send(self, ep, user, baseline=None, swap=None):
        """Send request as user (or as-is for baseline). swap=(orig, new)
        replaces an object ID in path/body for object-swap BOLA tests.
        Respects the configured replay delay (rate limiting)."""
        res = Result(ep, user or User("(baseline)", "-"))
        try:
            delay = self.replay_delay()
            if delay:
                time.sleep(delay / 1000.0)
            if user is None:
                req_str = re.sub(r"(?im)^Accept-Encoding:.*\r?\n", "", ep.request)
                req = self.helpers.stringToBytes(req_str)
            else:
                csrf_target = RequestBuilder.find_csrf_target(ep)
                csrf_value = None
                if csrf_target and user.headers.get("X-CSRF-Token"):
                    csrf_value = user.headers["X-CSRF-Token"]
                req_str = self.builder.build(ep, user, csrf_value=csrf_value,
                                             csrf_target=csrf_target if csrf_value else None)
                if swap:
                    orig, new = swap
                    head, sep, body = req_str.partition("\r\n\r\n")
                    head = head.replace(orig, new, 1)  # request line path
                    req_str = head + sep + body
                req = self.helpers.stringToBytes(req_str)
            svc = self.helpers.buildHttpService(ep.host, ep.port, ep.ssl)
            resp = self.callbacks.makeHttpRequest(svc, req)
            res.request = self.helpers.bytesToString(req)
            if resp.getResponse() is None:
                res.verdict = V_ERROR
                res.error = "no response"
                return res
            resp_bytes = resp.getResponse()
            res.response = self.helpers.bytesToString(resp_bytes)
            analyzed = self.helpers.analyzeResponse(resp_bytes)
            res.status = analyzed.getStatusCode()
            res.length = len(resp_bytes) - analyzed.getBodyOffset()
            if baseline and baseline.response:
                b_info = self.helpers.analyzeResponse(
                    self.helpers.stringToBytes(baseline.response))
                b_body = baseline.response[b_info.getBodyOffset():]
                a_body = res.response[analyzed.getBodyOffset():]
                if self.tab.chk_mask.isSelected():
                    res.similarity = body_similarity(a_body, b_body)
                else:
                    res.similarity = 1.0 if a_body == b_body else 0.0
        except Exception as e:
            res.verdict = V_ERROR
            res.error = str(e)
            traceback.print_exc()
        return res

    def _classify(self, ep, user, res, baseline):
        if res.verdict == V_ERROR:
            return V_ERROR
        s = res.status
        blocked = s in (401, 403) or (300 <= s < 400 and s not in (304,))
        allowed_role = self.is_allowed(ep, user.role)
        if blocked:
            return V_BLOCKED
        if 200 <= s < 400:
            if self._denied_by_content(res):
                # 200 but body says denied -> treat as blocked
                return V_BLOCKED
            rbody = res.response[res.response.find("\r\n\r\n") + 4:] if res.response else ""
            if is_empty_success(s, rbody):
                # 200 with empty body/collection = row-level filtering
                return V_BLOCKED
            # if very similar to the authenticated baseline body but role is a
            # 403/401-style response is handled above; here check role perms
            if allowed_role:
                return V_ALLOWED
            if ep.endpoint_key in self.permissions and user.role in self.permissions[ep.endpoint_key]:
                # explicitly denied -> finding
                return V_FINDING
            # no policy defined -> unverified 2xx
            return V_UNVERIFIED
        if 400 <= s < 500:
            return V_BLOCKED if s in (401, 403) else V_SKIPPED
        return V_SKIPPED

    # ---------------- export ----------------
    def export_csv(self):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.tab.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = str(chooser.getSelectedFile().getAbsolutePath())
        if not path.endswith(".csv"):
            path += ".csv"
        rows = ["endpoint_id,method,path,category,score,identity,verdict,status,"
                "length,len_diff_vs_baseline,similarity,note"]
        for (ep_id, ident), r in sorted(self.tab.table_model.results.items()):
            if ep_id == "(baseline)":
                continue
            base = self.tab.table_model.results.get((ep_id, "(baseline)"))
            d = (r.length - base.length) if base is not None else ""
            note = (r.error or "").replace('"', "'")
            rows.append('%d,%s,%s,"%s",%d,%s,%s,%d,%d,%s,%.2f,"%s"' % (
                r.endpoint.id, r.endpoint.method, r.endpoint.path.replace('"', "'"),
                r.endpoint.category(), endpoint_risk_score(r.endpoint),
                ident, r.verdict, r.status, r.length, d, r.similarity, note))
        with open(path, "w") as f:
            f.write("\n".join(rows).encode("utf-8"))
        JOptionPane.showMessageDialog(self.tab.panel, "Exported to %s" % path)

    def export_json(self):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.tab.panel) != JFileChooser.APPROVE_OPTION:
            return
        f = chooser.getSelectedFile()
        path = str(f.getAbsolutePath())
        if not path.endswith(".json"):
            path += ".json"
        data = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "roles": self.get_roles(),
            "users": [u.to_dict() for u in self.users],
            "permissions": self.permissions,
            "findings": [],
            "results": [],
        }
        for (ep_id, user_name), r in self.tab.table_model.results.items():
            item = {
                "endpoint_id": ep_id, "user": user_name,
                "verdict": r.verdict, "status": r.status,
                "length": r.length, "similarity": round(r.similarity, 3),
                "method": r.endpoint.method, "path": r.endpoint.path,
                "category": r.endpoint.category(),
            }
            data["results"].append(item)
            if r.verdict == V_FINDING:
                item["request"] = r.request
                item["response"] = r.response[:20000]
                data["findings"].append(item)
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        JOptionPane.showMessageDialog(self.tab.panel, "Exported to %s" % path)

    def export_html(self):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.tab.panel) != JFileChooser.APPROVE_OPTION:
            return
        f = chooser.getSelectedFile()
        path = str(f.getAbsolutePath())
        if not path.endswith(".html"):
            path += ".html"
        colors = {V_FINDING: "#d32f2f", V_BLOCKED: "#2e7d32", V_ALLOWED: "#799cb0",
                  V_UNVERIFIED: "#f57c00", V_ERROR: "#6a1b9a", V_SKIPPED: "#9e9e9e",
                  V_BOLA: "#c2185b", V_PUBLIC: "#0288d1", V_INFRA: "#7b1fa2"}
        cols = [c for c in self.tab.table_model.columns if c not in ("ID", "Endpoint", "Score")]
        rows = []
        for ep in self.endpoints:
            cells = ["<td>%s</td><td>%s</td>" % (ep.id, ep.label())]
            for u in cols:
                r = self.tab.table_model.results.get((ep.id, u))
                if r is None:
                    cells.append("<td></td>")
                else:
                    bg = colors.get(r.verdict, "#fff")
                    cells.append(
                        '<td style="background:%s;color:#fff" title="%s | %s">%d/%dB</td>' % (
                            bg, u.name, r.verdict, r.status, r.length))
            rows.append("<tr>%s</tr>" % "".join(cells))
        findings = ""
        n = 0
        for (ep_id, user_name), r in sorted(self.tab.table_model.results.items()):
            if r.verdict != V_FINDING:
                continue
            n += 1
            findings += ("<h3>Finding #%d: %s as %s (HTTP %d)</h3><p>Category: %s</p>"
                         "<pre>%s</pre>" % (
                             n, r.endpoint.label(), user_name, r.status,
                             r.endpoint.category(),
                             (r.request or "")[:4000].replace("&", "&amp;").replace("<", "&lt;")))
        html = """<html><head><title>Authorba Report</title>
<style>body{font-family:sans-serif}table{border-collapse:collapse}
td,th{border:1px solid #999;padding:4px 8px;font-size:12px}pre{background:#f4f4f4;padding:8px}
</style></head><body>
<h1>Authorba Report</h1>
<p>Generated: %s &nbsp;|&nbsp; Findings: <b>%d</b></p>
<table><tr><th>ID</th><th>Endpoint</th>%s</tr>
%s</table>
<h2>Findings detail</h2>%s
</body></html>""" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), n,
            "".join("<th>%s</th>" % c for c in cols),
            "\n".join(rows), findings)
        with open(path, "w") as fh:
            fh.write(html.encode("utf-8"))
        JOptionPane.showMessageDialog(self.tab.panel, "Exported to %s" % path)
